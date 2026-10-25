"""
DNS behavior detections — tunneling/exfiltration and C2 beaconing.

These look at the *pattern* of lookups from one internal host to one parent domain,
not at single queries: one long subdomain is normal, five hundred unique ones is a data channel.
"""

import re
import statistics
from collections import defaultdict

from . import config as cfg
from .detections import make_alert, shannon_entropy

# Public suffixes with two labels, so "evil.co.uk" is the parent, not "co.uk"
TWO_LABEL_SUFFIXES = {"co.uk", "org.uk", "ac.uk", "com.au", "net.au", "co.jp", "com.br", "co.za", "com.cn"}
ENCODED_LABEL = re.compile(r"^(?:[0-9a-f]{16,}|[a-z2-7]{24,}|[A-Za-z0-9+_-]{24,})$", re.IGNORECASE)


def split_domain(domain):
    """'a1b2.c3.exfil.example.com' → ('a1b2.c3.exfil', 'example.com')."""
    labels = domain.split(".")
    n = 3 if ".".join(labels[-2:]) in TWO_LABEL_SUFFIXES else 2
    return ".".join(labels[:-n]), ".".join(labels[-n:])


def by_host_and_parent(events):
    groups = defaultdict(list)
    for e in events:
        if e.source == "dns":
            sub, parent = split_domain(e.detail["domain"])
            if parent not in cfg.DNS_ALLOWLIST:
                groups[(e.ip, parent)].append((e, sub))
    return groups


# ── Tunneling / exfiltration ─────────────────────────────────────

def tunnel_signals(items):
    """Which tunneling indicators a host→domain conversation shows."""
    subs = [s for _, s in items if s]
    labels = [label for s in subs for label in s.split(".")]
    unique = len(set(subs))
    signals = {}
    if unique >= cfg.TUNNEL_MIN_UNIQUE:
        signals["many_unique_subdomains"] = unique
    long_queries = sum(1 for s in subs if len(s) >= cfg.TUNNEL_LONG_QUERY
                       or any(len(label) >= cfg.TUNNEL_LONG_LABEL for label in s.split(".")))
    if long_queries:
        signals["long_subdomains"] = long_queries
    encoded = sum(1 for label in labels if ENCODED_LABEL.match(label) and shannon_entropy(label) >= 3.0)
    if labels and encoded / len(labels) >= 0.3:
        signals["encoded_labels"] = encoded
    txt = sum(1 for e, _ in items if e.detail["qtype"].upper() in ("TXT", "NULL"))
    if txt / len(items) >= cfg.TUNNEL_TXT_RATIO:
        signals["txt_or_null_records"] = txt
    return signals


def detect_dns_tunneling(events):
    alerts = []
    for (ip, parent), items in by_host_and_parent(events).items():
        if len(items) < cfg.TUNNEL_MIN_QUERIES:
            continue
        signals = tunnel_signals(items)
        # One signal alone has innocent explanations (CDN hashes, DKIM/SPF TXT lookups); two together rarely do
        if len(signals) < 2:
            continue
        queries = [e for e, _ in items]
        encoded_chars = sum(len(s.replace(".", "")) for _, s in items)
        severity = "CRITICAL" if encoded_chars >= 10_000 else "HIGH"
        alerts.append(make_alert(
            "DNS_TUNNELING",
            "Possible DNS tunneling / exfiltration",
            ip, "internal host",
            severity,
            "T1048.003",
            queries,
            f"{len(queries)} lookups to {parent} with {len(signals)} tunneling signs "
            f"(~{encoded_chars / 1024:.1f} KB carried in subdomains)",
            parent_domain=parent,
            signals=signals,
            unique_subdomains=len({s for _, s in items}),
            encoded_bytes_estimate=encoded_chars,
            sample_queries=[e.detail["domain"] for e in queries[:3]],
        ))
    return alerts


# ── C2 beaconing ─────────────────────────────────────────────────

def beacon_stats(times):
    """Mean interval (s) and jitter (stdev / mean) between consecutive lookups."""
    gaps = [(b - a).total_seconds() for a, b in zip(times, times[1:])]
    mean = statistics.mean(gaps)
    jitter = statistics.pstdev(gaps) / mean if mean else float("inf")
    return mean, jitter


def detect_dns_beaconing(events):
    alerts = []
    for (ip, parent), items in by_host_and_parent(events).items():
        if len(items) < cfg.BEACON_MIN_QUERIES:
            continue
        queries = [e for e, _ in items]
        mean, jitter = beacon_stats([e.ts for e in queries])
        if mean < cfg.BEACON_MIN_INTERVAL or jitter > cfg.BEACON_MAX_JITTER:
            continue
        alerts.append(make_alert(
            "DNS_BEACONING",
            "Possible C2 beaconing",
            ip, "internal host",
            "HIGH" if jitter <= 0.05 else "MEDIUM",
            "T1071.004",
            queries,
            f"{len(queries)} lookups to {parent} every ~{mean:.0f}s (jitter {jitter:.0%}) "
            f"— regular timing suggests an implant checking in",
            parent_domain=parent,
            interval_seconds=round(mean, 1),
            jitter=round(jitter, 3),
            domains=sorted({e.detail["domain"] for e in queries}),
        ))
    return alerts
