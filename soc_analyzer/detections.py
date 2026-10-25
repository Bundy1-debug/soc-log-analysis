"""
Detection rules — each function takes normalized Events and returns alert dicts.
"""

import math
import re
from collections import Counter, defaultdict
from datetime import timedelta

from . import config as cfg
from .mitre import technique

SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


# ── Shared helpers ───────────────────────────────────────────────

def classify_severity(count, thresholds):
    if count >= thresholds[0]: return "CRITICAL"
    if count >= thresholds[1]: return "HIGH"
    if count >= thresholds[2]: return "MEDIUM"
    return "LOW"


def raise_severity(severity, steps=1):
    return SEVERITIES[min(SEVERITIES.index(severity) + steps, len(SEVERITIES) - 1)]


def at_least(severity, floor):
    return max(severity, floor, key=SEVERITIES.index)


def peak_in_window(times, seconds):
    """Largest number of events that fall inside any sliding window of `seconds` (times must be sorted)."""
    best, start = 0, 0
    for end in range(len(times)):
        while (times[end] - times[start]).total_seconds() > seconds:
            start += 1
        best = max(best, end - start + 1)
    return best


def describe(e):
    """One-line human summary of an event, used as alert evidence."""
    d = e.detail
    if e.source == "ssh":
        who = f"invalid user {e.user}" if d.get("invalid_user") else e.user
        verb = "Failed" if e.action == "failed" else "Accepted"
        return f"{verb} {d['method']} for {who}"
    if e.source == "http":
        path = d["path"] if len(d["path"]) <= 120 else d["path"][:117] + "..."
        return f"{d['method']} {path} -> {d['status']} ({d['agent'].split('/')[0] or '-'})"
    if e.source == "dns":
        return f"query {d['domain']} ({d['qtype']})"
    # host events
    if e.action in ("sudo_run", "sudo_fail"):
        return f"sudo by {e.user}: {d.get('command') or d.get('reason')}"
    if e.action in ("su_ok", "su_fail"):
        return f"su to {d['target']} by {e.user}" + (" (failed)" if e.action == "su_fail" else "")
    if e.action == "user_add":
        return f"{d['proc']}: new user {e.user}"
    if e.action == "group_add":
        return f"{d['proc']}: added {e.user} to group {d['group']}"
    return f"{e.action} {e.user}"


def evidence(events):
    """Keep the first and the last events: the start of an attack and how it ended."""
    keep = events if len(events) <= cfg.MAX_EVIDENCE else events[:cfg.MAX_EVIDENCE - 5] + events[-5:]
    return [{"ts": e.ts.isoformat(sep=" "), "source": e.source, "line": e.line_no, "text": describe(e)}
            for e in keep]


def make_alert(type_, title, ip, ip_role, severity, technique_id, events, summary, **details):
    return {
        "type":       type_,
        "title":      title,
        "ip":         ip,
        "ip_role":    ip_role,
        "severity":   severity,
        "mitre":      technique(technique_id),
        "count":      len(events),
        "first_seen": events[0].ts.isoformat(sep=" "),
        "last_seen":  events[-1].ts.isoformat(sep=" "),
        "summary":    summary,
        "details":    details,
        "evidence":   evidence(events),
    }


def by_ip(events, source, action):
    groups = defaultdict(list)
    for e in events:
        if e.source == source and e.action == action:
            groups[e.ip].append(e)
    return groups


# ── SSH ──────────────────────────────────────────────────────────

def detect_ssh_brute_force(events):
    alerts = []
    for ip, fails in by_ip(events, "ssh", "failed").items():
        peak = peak_in_window([e.ts for e in fails], cfg.SSH_WINDOW_SECONDS)
        if peak < cfg.SSH_FAIL_THRESHOLD:
            continue

        attempts = Counter(e.user for e in fails)
        invalid = {e.user for e in fails if e.detail["invalid_user"]}
        spraying = (len(attempts) >= cfg.SPRAY_MIN_USERS
                    and len(fails) / len(attempts) <= cfg.SPRAY_MAX_PER_USER)

        alerts.append(make_alert(
            "SSH_BRUTE_FORCE",
            "SSH password spraying" if spraying else "SSH brute force",
            ip, "attacker",
            classify_severity(len(fails), cfg.SSH_SEVERITY),
            "T1110.003" if spraying else "T1110.001",
            fails,
            f"{len(fails)} failed SSH logins (peak {peak} in {cfg.SSH_WINDOW_SECONDS}s) "
            f"against {len(attempts)} account(s)",
            peak_in_window=peak,
            window_seconds=cfg.SSH_WINDOW_SECONDS,
            users_targeted=[{"user": u, "attempts": n, "exists": u not in invalid}
                            for u, n in attempts.most_common()],
        ))
    return alerts


def detect_ssh_breach(events):
    """A successful login preceded by a brute force from the same IP = likely compromised account."""
    fails = by_ip(events, "ssh", "failed")
    lookback = timedelta(hours=cfg.BREACH_LOOKBACK_HOURS)
    alerts = []
    for ip, successes in by_ip(events, "ssh", "accepted").items():
        breaches = []
        for ok in successes:
            before = [f for f in fails.get(ip, []) if ok.ts - lookback <= f.ts <= ok.ts]
            if len(before) >= cfg.SSH_FAIL_THRESHOLD:
                breaches.append((ok, before))
        if not breaches:
            continue

        first_ok, before = breaches[0]
        targeted = {f.user for f in before}
        users = sorted({ok.user for ok, _ in breaches})
        alerts.append(make_alert(
            "SSH_LOGIN_AFTER_BRUTE_FORCE",
            "Successful SSH login after brute force",
            ip, "attacker",
            "CRITICAL",
            "T1078",
            [ok for ok, _ in breaches],
            f"Logged in as {', '.join(users)} after {len(before)} failed attempts "
            f"— treat the account as compromised",
            compromised_users=users,
            failures_before=len(before),
            user_was_targeted=first_ok.user in targeted,
            auth_method=first_ok.detail["method"],
        ))
    return alerts


# ── HTTP ─────────────────────────────────────────────────────────

SUSPICIOUS_PATHS = re.compile(
    r"(/wp-login\.php|/phpmyadmin|/admin|/shell\.php|/\.env|/etc/passwd"
    r"|/backup|/config|/\.git|/xmlrpc\.php|/cgi-bin)",
    re.IGNORECASE,
)
# Files that should never be served: a 2xx here means data may have leaked
EXPOSURE_PATHS = re.compile(r"(/\.env|/\.git|/etc/passwd|/backup|/config|/shell\.php)", re.IGNORECASE)
SCANNER_AGENTS = re.compile(
    r"(sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster|wpscan|nuclei|hydra|medusa)", re.IGNORECASE
)
# Scripted clients are context only: health checks and admins use curl too
SCRIPT_AGENTS = re.compile(r"(python-requests|curl|wget|go-http-client)", re.IGNORECASE)
ATTACK_PAYLOADS = {
    "sql_injection":     re.compile(r"(union\s+(all\s+)?select|\b(or|and)\b\s+'?\d+'?\s*=\s*'?\d+|information_schema|sleep\(\d)", re.IGNORECASE),
    "xss":               re.compile(r"(<script|javascript:|onerror\s*=|onload\s*=)", re.IGNORECASE),
    "path_traversal":    re.compile(r"(\.\./|\.\.\\)"),
    "command_injection": re.compile(r"(;\s*(cat|id|whoami|uname|wget|curl)\b|\|\s*(sh|bash)\b|\$\(|`)", re.IGNORECASE),
    # ${jndi:...} and its obfuscated forms like ${${lower:j}ndi:...}
    "log4shell":         re.compile(r"\$\{[^}]*j[^}]*n[^}]*d[^}]*i", re.IGNORECASE),
    "shellshock":        re.compile(r"\(\)\s*\{\s*[:;]"),
    # Local/remote file inclusion: PHP wrappers, system files, a URL passed to an include-style parameter
    "file_inclusion":    re.compile(r"(php://(filter|input)|file://|data://|expect://|/etc/(passwd|shadow)"
                                    r"|[?&](page|file|include|inc|path|template|doc|lang)=(https?|ftp)://)", re.IGNORECASE),
    # Server-side request forgery: cloud metadata endpoints, loopback passed in a parameter
    "ssrf":              re.compile(r"(169\.254\.169\.254|metadata\.google\.internal"
                                    r"|[?&][\w-]+=(https?://)?(127\.0\.0\.1|localhost|0\.0\.0\.0|\[::1\]))", re.IGNORECASE),
}


# Payloads that lead straight to code execution or cloud credential theft when they work
HIGH_IMPACT_PAYLOADS = {"log4shell", "shellshock", "command_injection", "file_inclusion", "ssrf"}


def http_indicators(e):
    """Why a single request is suspicious (empty list = not suspicious)."""
    path, agent = e.detail["path"], e.detail["agent"]
    found = []
    if SUSPICIOUS_PATHS.search(path):
        found.append("sensitive_path")
    if SCANNER_AGENTS.search(agent):
        found.append("scanner_agent")
    target = f"{path} {agent}"                     # payloads also hide in the User-Agent (Log4Shell, Shellshock)
    found += [name for name, rx in ATTACK_PAYLOADS.items() if rx.search(target)]
    if found and EXPOSURE_PATHS.search(path) and 200 <= e.detail["status"] < 300:
        found.append("possible_exposure")
    return found


def detect_http(events):
    hits = defaultdict(list)
    for e in events:
        if e.source == "http" and e.action == "request":
            reasons = http_indicators(e)
            if reasons:
                hits[e.ip].append((e, reasons))

    alerts = []
    for ip, items in hits.items():
        reqs = [e for e, _ in items]
        peak = peak_in_window([e.ts for e in reqs], cfg.HTTP_WINDOW_SECONDS)
        if peak < cfg.HTTP_THRESHOLD:
            continue

        reasons = Counter(r for _, rs in items for r in rs)
        payloads = sorted(r for r in reasons if r in ATTACK_PAYLOADS)
        exposed = sorted({e.detail["path"] for e, rs in items if "possible_exposure" in rs})
        severity = classify_severity(len(reqs), cfg.HTTP_SEVERITY)
        if payloads:
            severity = raise_severity(severity)
        if set(payloads) & HIGH_IMPACT_PAYLOADS:
            severity = at_least(severity, "HIGH")
        if exposed:
            severity = raise_severity(severity)
        if not payloads and severity == "CRITICAL":     # looking around is not breaking in
            severity = "HIGH"

        agents = sorted({e.detail["agent"].split("/")[0] for e in reqs if e.detail["agent"]})
        alerts.append(make_alert(
            "HTTP_SCAN",
            "Web exploitation attempts" if payloads else "Web vulnerability scan",
            ip, "attacker",
            severity,
            "T1190" if payloads else "T1595.002",
            reqs,
            f"{len(reqs)} suspicious web requests"
            + (f" with {', '.join(p.replace('_', ' ') for p in payloads)} payloads" if payloads else "")
            + (f"; {len(exposed)} sensitive file(s) answered 2xx" if exposed else ""),
            indicators=dict(reasons),
            payloads=payloads,
            exposed_paths=exposed,
            top_paths=[p for p, _ in Counter(e.detail["path"] for e in reqs).most_common(5)],
            distinct_paths=len({e.detail["path"] for e in reqs}),
            agents=agents,
            scripted_client=any(SCRIPT_AGENTS.search(a) for a in agents),
        ))
    return alerts


# ── DNS ──────────────────────────────────────────────────────────

SUSPICIOUS_TLDS = {"ru", "cc", "tk", "xyz", "top", "pw", "su", "cn"}
MALWARE_WORDS = {"malware", "botnet", "c2", "cnc", "phishing", "ransomware",
                 "trojan", "exploit", "payload", "dropper"}


def shannon_entropy(text):
    counts = Counter(text)
    return -sum(n / len(text) * math.log2(n / len(text)) for n in counts.values())


def dns_indicators(domain, intel):
    labels = domain.split(".")
    words = set(re.split(r"[.\-_]", domain))      # whole words only: "ec2" is not "c2"
    found = []
    if intel and intel.domain_match(domain):
        found.append("threat_intel")
    if words & MALWARE_WORDS:
        found.append("malware_keyword")
    if labels[-1] in SUSPICIOUS_TLDS:
        found.append("suspicious_tld")
    longest = max(labels[:-1] or labels, key=len)
    if len(longest) >= cfg.DGA_MIN_LENGTH and shannon_entropy(longest) >= cfg.DGA_ENTROPY:
        found.append("dga_like")
    # A TLD on its own is weak evidence — it needs another indicator to count
    return [] if found == ["suspicious_tld"] else found


def detect_dns(events, intel=None):
    hits = defaultdict(list)
    for e in events:
        if e.source == "dns":
            reasons = dns_indicators(e.detail["domain"], intel)
            if reasons:
                hits[e.ip].append((e, reasons))

    alerts = []
    for ip, items in hits.items():
        if len(items) < cfg.DNS_THRESHOLD:
            continue
        queries = [e for e, _ in items]
        reasons = Counter(r for _, rs in items for r in rs)
        severity = classify_severity(len(queries), cfg.DNS_SEVERITY)
        if "threat_intel" in reasons:
            severity = at_least(severity, "HIGH")
        dga_only = "dga_like" in reasons and not ({"threat_intel", "malware_keyword"} & set(reasons))

        alerts.append(make_alert(
            "SUSPICIOUS_DNS",
            "Possible DGA domains" if dga_only else "Suspicious DNS lookups",
            ip, "internal host",               # in DNS logs the IP is the machine asking — maybe infected
            severity,
            "T1568.002" if dga_only else "T1071.004",
            queries,
            f"{len(queries)} lookup(s) of suspicious domains"
            + (" (known-bad per threat intel)" if "threat_intel" in reasons else ""),
            indicators=dict(reasons),
            domains=sorted({e.detail["domain"] for e in queries}),
        ))
    return alerts


# ── Threat intel on source IPs ───────────────────────────────────

def apply_ip_intel(alerts, intel):
    for a in alerts:
        a["intel_match"] = bool(intel and intel.ip_match(a["ip"]))
        if a["intel_match"]:
            a["severity"] = raise_severity(a["severity"])
            a["summary"] += " — source IP is on the threat-intel blocklist"
    return alerts
