"""
EDR-style detections from auditd command execution (Pack 4).

auditd records every program run on the host. These rules read the reconstructed command
line of each exec event and match attacker behavior — the host-level view a log-only tool
usually lacks. One matching command is enough to raise an alert; alerts are grouped by user.

Each rule: name -> (compiled regex, technique, severity, one-line title).
"""

import re
from collections import defaultdict

from .detections import SEVERITIES, make_alert

RULES = {
    "reverse_shell": (
        re.compile(r"(/dev/tcp/|/dev/udp/"
                   r"|\bnc\b[^|&;]*\s-[a-z]*e\b"                 # nc -e /bin/sh
                   r"|\bncat\b[^|&;]*--exec"
                   r"|socket\.socket\([^)]*\).*(connect|dup2)"   # python reverse shell
                   r"|pty\.spawn\("
                   r"|bash\s+-i\b|sh\s+-i\b)", re.IGNORECASE),
        "T1059.004", "CRITICAL", "Reverse shell"),

    "download_and_run": (
        re.compile(r"(\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba)?sh\b"   # curl … | bash
                   r"|\b(curl|wget)\b.*&&.*\b(ba)?sh\b"
                   r"|\b(ba)?sh\s+/tmp/|\b/tmp/\S+\.(sh|py|pl|elf|bin)\b"  # run from /tmp
                   r"|\bchmod\s+[+0-7]*x\s+/tmp/)", re.IGNORECASE),
        "T1105", "HIGH", "Download-and-run / staged binary"),

    "credential_access_files": (
        re.compile(r"(/etc/shadow\b|/etc/gshadow\b"
                   r"|\b(cat|cp|scp|less|more|head|tail|strings)\b[^|&;]*/etc/shadow)", re.IGNORECASE),
        "T1003.008", "CRITICAL", "Access to /etc/shadow"),

    "private_keys": (
        re.compile(r"(\.ssh/id_(rsa|ed25519|ecdsa|dsa)\b"
                   r"|\.aws/credentials\b|\.config/gcloud/|\.kube/config\b"
                   r"|\b(cat|cp|scp|tar|zip)\b[^|&;]*\.ssh/)", re.IGNORECASE),
        "T1552.004", "HIGH", "Access to private keys / cloud credentials"),

    "cron_persistence": (
        re.compile(r"(\bcrontab\s+-|/etc/cron\.|/var/spool/cron/|/etc/crontab\b)", re.IGNORECASE),
        "T1053.003", "HIGH", "Cron persistence"),

    "ssh_key_persistence": (
        re.compile(r"(authorized_keys\b"
                   r"|echo\b[^|&;]*>>?[^|&;]*\.ssh/"
                   r"|ssh-keygen\b)", re.IGNORECASE),
        "T1098.004", "HIGH", "SSH authorized_keys change"),

    "service_persistence": (
        re.compile(r"(systemctl\s+(enable|--now)\b"
                   r"|/etc/systemd/system/|/lib/systemd/system/"
                   r"|/etc/init\.d/|/etc/rc\.local\b)", re.IGNORECASE),
        "T1543.002", "HIGH", "Systemd / init persistence"),

    "clear_logs": (
        re.compile(r"((\brm\b|\btruncate\b|>\s*)[^|&;]*/var/log/"
                   r"|\bjournalctl\b[^|&;]*--vacuum"
                   r"|:\s*>\s*/var/log/)", re.IGNORECASE),
        "T1070.002", "CRITICAL", "Log clearing"),

    "clear_history": (
        re.compile(r"(history\s+-c\b"
                   r"|unset\s+HISTFILE\b|export\s+HISTFILE=/dev/null"
                   r"|\brm\b[^|&;]*\.bash_history|>\s*~?/?\.bash_history)", re.IGNORECASE),
        "T1070.003", "HIGH", "Command-history clearing"),
}


def match_rules(command):
    return [name for name, (rx, *_) in RULES.items() if rx.search(command)]


def detect_edr(events):
    """One alert per (user, rule): the command(s) that matched, newest-worst first."""
    hits = defaultdict(list)                                  # (user, rule) -> [events]
    for e in events:
        if e.source == "host" and e.action == "exec":
            for rule in match_rules(e.detail["command"]):
                hits[(e.user, rule)].append(e)

    alerts = []
    for (user, rule), evs in hits.items():
        _, technique, severity, title = RULES[rule]
        commands = [e.detail["command"] for e in evs]
        alerts.append(make_alert(
            f"EDR_{rule.upper()}",
            title,
            user, "local user",
            severity,
            technique,
            evs,
            f"{title} by '{user}': {len(commands)} command(s) matched",
            rule=rule,
            commands=commands[:5],
            exe=sorted({e.detail["exe"] for e in evs if e.detail["exe"]}),
        ))
    return sorted(alerts, key=lambda a: -SEVERITIES.index(a["severity"]))
