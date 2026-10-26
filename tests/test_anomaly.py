from datetime import datetime, timedelta
from pathlib import Path

from soc_analyzer import analyze_files
from soc_analyzer.anomaly import detect_new_entities, detect_volume_outliers
from soc_analyzer.parsers import parse_lines

SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "anomaly_baseline.log"


def web(ts, ip, path="/"):
    return f'{ip} - - [{ts:%d/%b/%Y:%H:%M:%S} +0000] "GET {path} HTTP/1.1" 200 2000 "-" "Mozilla/5.0"'


def dns(ts, ip, domain):
    return f"{ts:%b %d %H:%M:%S} ubuntu named[1]: query: {domain} IN A + ({ip})"


# ── Volume outlier ───────────────────────────────────────────────

def test_volume_outlier_flagged():
    t = datetime(2024, 4, 2, 9, 0, 0)
    lines = []
    for n in range(10):                                    # 10 quiet peers, ~5 events each
        for i in range(5):
            lines.append(web(t + timedelta(seconds=n * 300 + i), f"10.0.0.{n}"))
    for i in range(60):                                    # one loud source
        lines.append(web(t + timedelta(seconds=i), "10.0.0.200"))
    [alert] = detect_volume_outliers(parse_lines(lines, year=2024))
    assert alert["ip"] == "10.0.0.200"
    assert alert["details"]["zscore"] >= 3.0
    assert alert["mitre"]["technique_id"] == "N/A"


def test_no_outlier_when_everyone_is_similar():
    t = datetime(2024, 4, 2, 9, 0, 0)
    lines = [web(t + timedelta(seconds=n * 60 + i), f"10.0.0.{n}")
             for n in range(10) for i in range(55)]        # all ~equal volume
    assert detect_volume_outliers(parse_lines(lines, year=2024)) == []


def test_too_few_sources_is_not_judged():
    t = datetime(2024, 4, 2, 9, 0, 0)
    lines = [web(t + timedelta(seconds=i), "10.0.0.1") for i in range(60)]
    assert detect_volume_outliers(parse_lines(lines, year=2024)) == []


# ── New entities (baseline split) ────────────────────────────────

def test_new_source_and_domain_after_baseline():
    t = datetime(2024, 4, 2, 8, 0, 0)
    lines = []
    for m in range(0, 120, 2):                             # 2h baseline: known IPs + domains
        ts = t + timedelta(minutes=m)
        lines.append(web(ts, f"203.0.113.{10 + m % 5}"))
        lines.append(dns(ts, "192.168.1.10", "known.example.com"))
    recent = t + timedelta(hours=2, minutes=10)
    for i in range(5):                                     # new source in recent window
        lines.append(web(recent + timedelta(seconds=i * 5), "203.0.113.250"))
    for i, dom in enumerate(["a.new.io", "b.new.io", "c.new.io"]):
        lines.append(dns(recent + timedelta(minutes=i), "192.168.1.11", dom))

    alerts = {a["type"]: a for a in detect_new_entities(parse_lines(lines, year=2024))}
    assert alerts["ANOMALY_NEW_SOURCE"]["ip"] == "203.0.113.250"
    assert set(alerts["ANOMALY_NEW_DOMAIN"]["details"]["domains"]) == {"a.new.io", "b.new.io", "c.new.io"}


def test_concatenated_logs_only_analyze_latest_segment():
    # An old capture, then a >6h gap, then a fresh continuous capture with a new source.
    old = datetime(2024, 3, 1, 9, 0, 0)
    new = datetime(2024, 3, 10, 9, 0, 0)       # 9 days later = separate capture
    lines = [web(old + timedelta(minutes=m), f"203.0.113.{10 + m % 5}") for m in range(0, 180, 5)]
    for m in range(0, 150, 2):                 # fresh baseline
        lines.append(web(new + timedelta(minutes=m), f"198.51.100.{20 + m % 4}"))
    for i in range(5):                         # new source late in the fresh capture
        lines.append(web(new + timedelta(hours=2, minutes=20, seconds=i), "198.51.100.99"))
    alerts = detect_new_entities(parse_lines(lines, year=2024))
    # the old-capture IPs must not be reported as "new" just because they precede the gap
    assert {a["ip"] for a in alerts} == {"198.51.100.99"}


def test_short_log_has_no_baseline():
    t = datetime(2024, 4, 2, 9, 0, 0)
    lines = [web(t + timedelta(seconds=i), "203.0.113.9") for i in range(40)]   # < 2h span
    assert detect_new_entities(parse_lines(lines, year=2024)) == []


# ── Sample end to end ────────────────────────────────────────────

def test_anomaly_sample_end_to_end():
    report = analyze_files([SAMPLE])
    by_type = {a["type"]: a for a in report["alerts"]}
    assert set(by_type) == {"ANOMALY_VOLUME", "ANOMALY_NEW_SOURCE", "ANOMALY_NEW_DOMAIN"}
    assert by_type["ANOMALY_VOLUME"]["ip"] == "198.51.100.231"
    assert by_type["ANOMALY_NEW_DOMAIN"]["ip"] == "192.168.1.40"
    # volume outlier + new source for the same IP correlate into one incident
    inc = next(i for i in report["incidents"] if i["ip"] == "198.51.100.231")
    assert len(inc["alert_ids"]) == 2
