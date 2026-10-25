from datetime import datetime, timedelta
from pathlib import Path

from soc_analyzer import analyze_files
from soc_analyzer.detections_dns import detect_dns_beaconing, detect_dns_tunneling, split_domain
from soc_analyzer.parsers import parse_lines

SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "dns_exfil_c2.log"
T0 = datetime(2026, 3, 20, 12, 0, 0)


def q(seconds, domain, client="10.1.1.5", qtype="A"):
    ts = T0 + timedelta(seconds=seconds)
    return f"{ts:%b %d %H:%M:%S} ubuntu named[1]: query: {domain} IN {qtype} + ({client})"


def parse(lines):
    return parse_lines(lines, year=2026)


def test_split_domain():
    assert split_domain("a.b.example.com") == ("a.b", "example.com")
    assert split_domain("x.evil.co.uk") == ("x", "evil.co.uk")


# ── Tunneling ────────────────────────────────────────────────────

def test_encoded_unique_subdomains_are_tunneling():
    lines = [q(i, f"{i:04x}{'a1b2c3d4e5f60718' * 2}.data.tunnel.example", qtype="TXT") for i in range(30)]
    [alert] = detect_dns_tunneling(parse(lines))
    assert alert["mitre"]["technique_id"] == "T1048.003"
    assert alert["details"]["parent_domain"] == "tunnel.example"
    assert {"many_unique_subdomains", "encoded_labels", "txt_or_null_records"} <= set(alert["details"]["signals"])


def test_cdn_style_hashes_alone_are_not_tunneling():
    # Many unique short hashed hostnames, normal A records: one signal only
    lines = [q(i * 5, f"img{i}.static.shop.example") for i in range(40)]
    assert detect_dns_tunneling(parse(lines)) == []


def test_allowlisted_parent_is_ignored():
    lines = [q(i, f"{i:04x}{'a1b2c3d4e5f60718' * 2}.cloudfront.net", qtype="TXT") for i in range(30)]
    assert detect_dns_tunneling(parse(lines)) == []


# ── Beaconing ────────────────────────────────────────────────────

def test_regular_lookups_are_beaconing():
    lines = [q(i * 60 + (i % 2), "check.c2.example") for i in range(10)]
    [alert] = detect_dns_beaconing(parse(lines))
    assert 59 <= alert["details"]["interval_seconds"] <= 61
    assert alert["severity"] == "HIGH"


def test_irregular_lookups_are_not_beaconing():
    gaps = [5, 300, 12, 900, 40, 7, 600, 33, 2]
    t, lines = 0, []
    for g in gaps:
        t += g
        lines.append(q(t, "www.news.example"))
    assert detect_dns_beaconing(parse(lines)) == []


def test_bursts_are_not_beaconing():
    lines = [q(i, "api.app.example") for i in range(20)]      # every 1s = burst, not a beacon
    assert detect_dns_beaconing(parse(lines)) == []


# ── Sample end to end ────────────────────────────────────────────

def test_dns_sample_end_to_end():
    report = analyze_files([SAMPLE], year=2024)
    by_type = {a["type"]: a for a in report["alerts"]}
    assert by_type["DNS_TUNNELING"]["ip"] == "192.168.1.77"
    assert by_type["DNS_BEACONING"]["ip"] == "192.168.1.88"
    assert "192.168.1.10" not in {a["ip"] for a in report["alerts"]}     # normal browsing + CDN stay quiet
    assert not any(a["mitre"]["technique_id"] == "T1568.002" and a["ip"] == "192.168.1.77"
                   for a in report["alerts"])                          # no duplicate DGA alert
