"""
Anomaly detection (Pack 5) — statistics instead of signatures.

Signature rules only catch attacks someone described in advance. These two detectors
catch the *unusual*: a host far busier than its peers, and entities never seen before.
They are deliberately conservative (MEDIUM/LOW) and gated so they stay quiet unless the
data is rich enough to judge — a short burst of logs has no baseline to learn from.

This is the idea behind UEBA (User and Entity Behavior Analytics) in a modern SIEM.
"""

import statistics
from collections import Counter, defaultdict

from . import config as cfg
from .detections import make_alert

NETWORK_ACTIONS = ("failed", "request", "query")
SEGMENT_GAP_HOURS = 6      # a quiet gap longer than this means a separate capture


def latest_segment(events):
    """
    Return the most recent run of events with no gap longer than SEGMENT_GAP_HOURS.

    Baselining assumes one continuous capture. If several unrelated logs are concatenated
    (e.g. different days), analysing across the gap makes every later entity look "new";
    this isolates the current capture instead.
    """
    if not events:
        return events
    ordered = sorted(events, key=lambda e: e.ts)
    start = 0
    for i in range(1, len(ordered)):
        if (ordered[i].ts - ordered[i - 1].ts).total_seconds() > SEGMENT_GAP_HOURS * 3600:
            start = i
    return ordered[start:]


def _zscores(counts):
    values = list(counts.values())
    if len(values) < 2:
        return {}
    mean, sd = statistics.mean(values), statistics.pstdev(values)
    if sd == 0:
        return {}
    return {k: (v - mean) / sd for k, v in counts.items()}


def detect_volume_outliers(events):
    """Flag an IP whose event count is a statistical outlier versus its peers."""
    events = latest_segment(events)
    net = [e for e in events if e.ip and e.action in NETWORK_ACTIONS]
    counts = Counter(e.ip for e in net)
    if len(counts) < cfg.ANOM_MIN_ENTITIES:
        return []
    z = _zscores(counts)
    mean = statistics.mean(counts.values())

    alerts = []
    for ip, count in counts.items():
        if count >= cfg.ANOM_MIN_EVENTS and z.get(ip, 0) >= cfg.ANOM_Z:
            evs = [e for e in net if e.ip == ip]
            alerts.append(make_alert(
                "ANOMALY_VOLUME",
                "Unusual activity volume",
                ip, "host or source",
                "MEDIUM",
                None,
                evs,
                f"{ip} generated {count} events, {count / mean:.0f}x the average of {mean:.0f} "
                f"across {len(counts)} sources (z={z[ip]:.1f})",
                event_count=count,
                peer_average=round(mean, 1),
                zscore=round(z[ip], 1),
            ))
    return alerts


def detect_new_entities(events):
    """
    Split the timeline into baseline (earlier) and recent (later); flag source IPs and
    domains that appear only in the recent window. Gated: needs a real baseline.
    """
    events = latest_segment(events)
    times = [e.ts for e in events]
    if not times:
        return []
    span = max(times) - min(times)
    if span.total_seconds() < cfg.ANOM_MIN_SPAN_HOURS * 3600:
        return []
    cut = min(times) + span * cfg.ANOM_BASELINE_FRAC
    baseline = [e for e in events if e.ts < cut]
    recent = [e for e in events if e.ts >= cut]
    if len(baseline) < cfg.ANOM_MIN_BASELINE:
        return []

    alerts = []

    # New external source IPs (SSH / HTTP)
    base_ips = {e.ip for e in baseline if e.source in ("ssh", "http") and e.ip}
    new_ips = defaultdict(list)
    for e in recent:
        if e.source in ("ssh", "http") and e.ip and e.ip not in base_ips:
            new_ips[e.ip].append(e)
    for ip, evs in new_ips.items():
        if len(evs) >= cfg.ANOM_NEW_MIN:
            alerts.append(make_alert(
                "ANOMALY_NEW_SOURCE",
                "New source not seen in baseline",
                ip, "source",
                "LOW",
                None,
                evs,
                f"{ip} made {len(evs)} request(s) but never appeared in the earlier baseline period",
                baseline_sources=len(base_ips),
            ))

    # New domains looked up by internal hosts (DNS)
    base_domains = {e.detail["domain"] for e in baseline if e.source == "dns"}
    new_domains = defaultdict(list)                       # querying host -> events
    for e in recent:
        if e.source == "dns" and e.detail["domain"] not in base_domains:
            new_domains[e.ip].append(e)
    for ip, evs in new_domains.items():
        if len(evs) >= cfg.ANOM_NEW_MIN:
            domains = sorted({e.detail["domain"] for e in evs})
            alerts.append(make_alert(
                "ANOMALY_NEW_DOMAIN",
                "New domains not seen in baseline",
                ip, "internal host",
                "LOW",
                None,
                evs,
                f"{ip} looked up {len(domains)} domain(s) never seen in the baseline period",
                domains=domains[:10],
                baseline_domains=len(base_domains),
            ))
    return alerts


def run_anomaly(events):
    return detect_volume_outliers(events) + detect_new_entities(events)
