"""
Engine — the pipeline: parse → detect → enrich → correlate → report.
Both the CLI and the web app call analyze(); neither has detection logic of its own.
"""

from collections import Counter
from datetime import datetime

from . import config as cfg
from .correlation import build_incidents
from .detections import (SEVERITIES, apply_ip_intel, detect_dns, detect_http,
                         detect_ssh_breach, detect_ssh_brute_force)
from .detections_dns import detect_dns_beaconing, detect_dns_tunneling, split_domain
from .detections_edr import detect_edr
from .detections_host import run_host
from .detections_web import (detect_directory_brute_force, detect_large_transfer,
                             detect_web_login_brute_force, detect_webshell)
from .intel import load_intel
from .parsers import parse_lines

VERSION = "3.1"


def suppress_overlaps(alerts):
    """Drop DGA-only alerts whose domains all belong to a channel already flagged as tunneling."""
    tunnels = {(a["ip"], a["details"]["parent_domain"]) for a in alerts if a["type"] == "DNS_TUNNELING"}

    def covered(a):
        return (a["type"] == "SUSPICIOUS_DNS" and a["mitre"]["technique_id"] == "T1568.002"
                and all((a["ip"], split_domain(d)[1]) in tunnels for d in a["details"]["domains"]))

    # A "scan" made only of login-page hits is the login brute force seen twice
    web_bf = {a["ip"]: set(a["details"]["login_paths"]) for a in alerts if a["type"] == "WEB_LOGIN_BRUTE_FORCE"}

    def login_only_scan(a):
        d = a["details"] if a["type"] == "HTTP_SCAN" else {}
        return (a["ip"] in web_bf and not d.get("payloads") and d.get("distinct_paths", 99) <= len(d.get("top_paths", []))
                and {p.split("?")[0] for p in d["top_paths"]} <= web_bf[a["ip"]])

    return [a for a in alerts if not covered(a) and not login_only_scan(a)]


def run_all(events, intel=None):
    alerts = (detect_ssh_brute_force(events) + detect_ssh_breach(events)
              + detect_http(events) + detect_dns(events, intel)
              + detect_dns_tunneling(events) + detect_dns_beaconing(events)
              + detect_web_login_brute_force(events) + detect_directory_brute_force(events)
              + detect_webshell(events) + detect_large_transfer(events)
              + run_host(events) + detect_edr(events))
    return apply_ip_intel(suppress_overlaps(alerts), intel)


def analyze(lines, sources=None, year=None, intel=None, geo=False):
    """
    lines   : iterable of raw log lines (auth.log, access.log, named log — mixed is fine)
    sources : names of the inputs, recorded in the report
    year    : year for syslog lines that carry none (default: inferred)
    intel   : ThreatIntel (default: load intel/ next to the package)
    geo     : add IP geolocation (sends IPs to ip-api.com)
    """
    lines = list(lines)
    intel = intel if intel is not None else load_intel(cfg.INTEL_DIR)

    events = [e for e in parse_lines(lines, year) if e.ip not in cfg.ALLOWLIST_IPS]
    alerts = run_all(events, intel)
    alerts.sort(key=lambda a: (-SEVERITIES.index(a["severity"]), a["first_seen"]))
    alerts = [{"id": f"ALR-{n:03d}", **a} for n, a in enumerate(alerts, 1)]
    incidents = build_incidents(alerts)

    if geo:
        from .geo import geolocate              # optional dependency: requests
        locations = geolocate({a["ip"] for a in alerts})
        for a in alerts:
            a["geo"] = locations.get(a["ip"], {})

    by_source = Counter(e.source for e in events)
    activity = Counter(e.ip for e in events
                       if e.action in ("failed", "request", "query"))
    flagged = {a["ip"] for a in alerts}

    return {
        "generated_at": datetime.now().isoformat(sep=" ", timespec="seconds"),
        "engine_version": VERSION,
        "inputs": sources or [],
        "summary": {
            "lines_read":       len(lines),
            "events_parsed":    len(events),
            "events_by_source": dict(by_source),
            "unique_ips":       len({e.ip for e in events if e.ip}),
            "ssh_failures":     sum(1 for e in events if e.source == "ssh" and e.action == "failed"),
            "ssh_successes":    sum(1 for e in events if e.source == "ssh" and e.action == "accepted"),
            "alerts":           len(alerts),
            "incidents":        len(incidents),
            "flagged_ips":      len(flagged),
            "breaches":         sum(1 for i in incidents if i["breach"]),
            "by_severity":      {s: sum(1 for a in alerts if a["severity"] == s) for s in reversed(SEVERITIES)},
            "by_type":          dict(Counter(a["type"] for a in alerts)),
            "by_tactic":        dict(Counter(a["mitre"]["tactic"] for a in alerts)),
            "top_ips":          [{"ip": ip, "events": n, "flagged": ip in flagged}
                                 for ip, n in activity.most_common(10)],
        },
        "incidents": incidents,
        "alerts": alerts,
    }


def analyze_files(paths, **kwargs):
    lines = []
    for path in paths:
        with open(path, errors="replace") as f:
            lines.extend(f)
    return analyze(lines, sources=[str(p) for p in paths], **kwargs)
