from datetime import datetime, timedelta
from pathlib import Path

from soc_analyzer import analyze_files
from soc_analyzer.detections_host import (detect_account_creation, detect_privilege_grant,
                                          detect_su_brute_force, detect_sudo_abuse)
from soc_analyzer.parsers import parse_lines

SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "host_privilege.log"
T0 = datetime(2026, 3, 22, 14, 0, 0)


def line(sec, proc, msg):
    ts = T0 + timedelta(seconds=sec)
    return f"{ts:%b %d %H:%M:%S} ubuntu {proc}[1]: {msg}"


def parse(lines):
    return parse_lines(lines, year=2026)


# ── Parsing ──────────────────────────────────────────────────────

def test_sudo_and_user_events_parse():
    events = parse([
        line(0, "sudo", "  bob : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/cat /etc/shadow"),
        line(1, "sudo", "  bob : 1 incorrect password attempts ; COMMAND=/bin/ls"),
        line(2, "useradd", "new user: name=svc, UID=1050, GID=1050, home=/home/svc, shell=/bin/bash"),
        line(3, "usermod", "add 'svc' to group 'sudo'"),
        line(4, "su", "FAILED su for root by eve"),
    ])
    actions = [(e.action, e.user) for e in events]
    assert ("sudo_run", "bob") in actions
    assert ("sudo_fail", "bob") in actions
    assert ("user_add", "svc") in actions
    assert ("group_add", "svc") in actions
    assert ("su_fail", "eve") in actions


def test_non_privileged_group_add_is_ignored():
    events = parse([line(0, "usermod", "add 'bob' to group 'docker'")])
    assert all(e.action != "group_add" for e in events)


# ── Detections ───────────────────────────────────────────────────

def test_not_in_sudoers_is_high():
    events = parse([line(0, "sudo", "  bob : user NOT in sudoers ; COMMAND=/bin/su")])
    [alert] = detect_sudo_abuse(events)
    assert alert["severity"] == "HIGH" and alert["details"]["not_in_sudoers"]
    assert alert["mitre"]["technique_id"] == "T1548.003"


def test_repeated_bad_sudo_password():
    events = parse([line(i, "sudo", "  bob : 1 incorrect password attempts ; COMMAND=/bin/ls") for i in range(3)])
    [alert] = detect_sudo_abuse(events)
    assert alert["count"] == 3


def test_single_sudo_failure_is_quiet():
    events = parse([line(0, "sudo", "  bob : 1 incorrect password attempts ; COMMAND=/bin/ls")])
    assert detect_sudo_abuse(events) == []


def test_su_brute_force():
    events = parse([line(i, "su", "FAILED su for root by eve") for i in range(4)])
    [alert] = detect_su_brute_force(events)
    assert alert["details"]["targets"] == ["root"]


def test_account_creation_and_priv_grant():
    events = parse([
        line(0, "useradd", "new user: name=svc, UID=1050, GID=1050, home=/home/svc, shell=/bin/sh"),
        line(1, "usermod", "add 'svc' to group 'sudo'"),
    ])
    [created] = detect_account_creation(events)
    [granted] = detect_privilege_grant(events)
    assert created["mitre"]["technique_id"] == "T1136.001"
    assert granted["mitre"]["technique_id"] == "T1098" and granted["details"]["groups"] == ["sudo"]


# ── Sample end to end ────────────────────────────────────────────

def test_host_sample_end_to_end():
    report = analyze_files([SAMPLE], year=2024)
    by_ip = {(a["ip"], a["type"]) for a in report["alerts"]}
    assert ("bob", "SUDO_ABUSE") in by_ip
    assert ("eve", "SU_BRUTE_FORCE") in by_ip
    assert ("svc_backup", "USER_CREATED") in by_ip
    assert ("svc_backup", "PRIV_GROUP_ADD") in by_ip
    assert "alice" not in {a["ip"] for a in report["alerts"]}       # one normal sudo stays quiet
    # account creation + privilege grant correlate into one per-user incident
    svc = next(i for i in report["incidents"] if i["ip"] == "svc_backup")
    assert set(svc["techniques"]) == {"T1136.001", "T1098"}
