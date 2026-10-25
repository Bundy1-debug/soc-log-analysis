from pathlib import Path

from soc_analyzer import analyze, analyze_files, format_text
from soc_analyzer import config as cfg

SAMPLE = Path(__file__).resolve().parent.parent / "sample_auth.log"


def test_sample_log_end_to_end():
    report = analyze_files([SAMPLE])
    incidents = {i["ip"]: i for i in report["incidents"]}

    # The attacker that brute-forced SSH and got in is one CRITICAL incident spanning several tactics
    top = incidents["192.168.1.105"]
    assert top["severity"] == "CRITICAL" and top["breach"]
    assert {"Credential Access", "Initial Access", "Command and Control"} <= set(top["tactics"])

    # The SQL injection line with spaces is no longer dropped
    assert "T1190" in incidents["203.0.113.42"]["techniques"]

    assert report["summary"]["breaches"] == 1
    assert report["incidents"][0]["id"] == "INC-001"


def test_allowlisted_ip_never_alerts(monkeypatch):
    monkeypatch.setattr(cfg, "ALLOWLIST_IPS", {"192.168.1.105"})
    report = analyze_files([SAMPLE])
    assert "192.168.1.105" not in {a["ip"] for a in report["alerts"]}


def test_empty_input():
    report = analyze([])
    assert report["alerts"] == [] and report["incidents"] == []
    assert "No threats detected" in format_text(report, color=False)
