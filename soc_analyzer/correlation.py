"""
Correlation — group alerts that share an IP into one incident with a timeline.

Analysts triage incidents, not alerts: "192.168.1.105 scanned the web server, brute-forced SSH,
logged in as root, then looked up a C2 domain" is one story, not four tickets.
"""

from collections import defaultdict

from .detections import SEVERITIES, raise_severity

MAX_TIMELINE = 40

# Response playbook: what a Tier-1 analyst should do for each alert type
PLAYBOOK = {
    "SSH_BRUTE_FORCE": [
        "Block {ip} at the firewall (or let fail2ban ban it)",
        "Confirm SSH password login is disabled (PasswordAuthentication no) and keys are enforced",
    ],
    "SSH_LOGIN_AFTER_BRUTE_FORCE": [
        "Treat the host as compromised: isolate it from the network",
        "Reset the password of {users} and kill their active sessions",
        "Review what the session did (bash history, auditd) and look for persistence: new users, authorized_keys, cron jobs",
    ],
    "HTTP_SCAN": [
        "Block or rate-limit {ip} at the WAF / reverse proxy",
        "Check whether exploited pages returned data (status 2xx, response size)",
    ],
    "HTTP_SCAN_EXPOSURE": [
        "Sensitive files were served ({paths}): rotate every secret they contain",
    ],
    "SUSPICIOUS_DNS": [
        "Investigate host {ip} for malware (EDR scan, running processes, outbound connections)",
        "Block or sinkhole the domains at the DNS resolver",
    ],
    "WEB_LOGIN_BRUTE_FORCE": [
        "Block {ip} and add rate limiting / CAPTCHA to the login form",
        "Enforce MFA on the application's accounts",
    ],
    "WEB_LOGIN_SUCCESS": [
        "Find which account logged in from {ip}, reset its password and end its sessions",
        "Review what that account did after login (admin actions, uploads, plugin installs)",
    ],
    "WEB_DIRECTORY_BRUTE_FORCE": [
        "Block {ip}; review the paths that answered 2xx/3xx during the scan ({paths})",
    ],
    "WEBSHELL": [
        "Treat the web server as compromised: isolate it",
        "Remove and preserve the script(s) for analysis: {scripts}",
        "Find how it was uploaded (upload form, vulnerable plugin) and look for other new files in the web root",
    ],
    "WEB_LARGE_TRANSFER": [
        "Confirm what was served to {ip} and whether it should be public",
        "If data files leaked, start the data-breach process and rotate any credentials they contain",
    ],
    "SUDO_ABUSE": [
        "Review what '{ip}' was trying to run with sudo and whether the account should have sudo at all",
        "Check /var/log/auth.log for a matching successful sudo right after the failures",
    ],
    "SU_BRUTE_FORCE": [
        "Investigate account '{ip}': repeated su failures suggest a guessed-at root/other password",
    ],
    "USER_CREATED": [
        "Confirm the new account '{ip}' maps to a change ticket; if not, disable it and investigate who created it",
        "Check the account for a password, SSH keys and sudo rights",
    ],
    "PRIV_GROUP_ADD": [
        "Confirm the privilege grant to '{ip}' was authorized; if not, remove it and treat the host as compromised",
        "Review recent commands run by '{ip}' and look for other persistence",
    ],
    "DNS_TUNNELING": [
        "Block {parent} at the DNS resolver to cut the channel",
        "Isolate host {ip} and find the process making the lookups (EDR, auditd, ss -p)",
        "Estimate what left: decode a sample of subdomains and check which files the process read",
    ],
    "DNS_BEACONING": [
        "Find the process on {ip} that resolves {parent} on a timer (EDR process tree, auditd)",
        "Block {parent} at the resolver and hunt for the same domain on other hosts",
    ],
    # EDR command-execution alerts share a response; a couple get an extra line
    "_EDR": [
        "Isolate the host and review the matched command(s) and their parent process in auditd",
        "Identify the user/session behind '{ip}' and what else it ran before and after",
    ],
    "EDR_REVERSE_SHELL": [
        "Treat the host as actively compromised: pull it off the network now",
        "Find the remote IP/port the shell connected to and block it; preserve volatile evidence",
    ],
    "EDR_CLEAR_LOGS": [
        "Logs may be incomplete: switch to other evidence (auditd, EDR, network, backups)",
    ],
    "_ANOMALY": [
        "Triage {ip}: anomalies are leads, not confirmed attacks — check what the activity was",
        "Compare against a longer baseline and the asset's normal role before escalating",
    ],
}


def _actions(alert):
    d = alert["details"]
    keys = [alert["type"]]
    if alert["type"] == "HTTP_SCAN" and d.get("exposed_paths"):
        keys.append("HTTP_SCAN_EXPOSURE")
    if alert["type"] == "WEB_LOGIN_BRUTE_FORCE" and d.get("successful_logins"):
        keys.append("WEB_LOGIN_SUCCESS")
    if alert["type"].startswith("EDR_"):               # generic EDR steps, plus any type-specific ones
        keys = ["_EDR"] + [k for k in [alert["type"]] if k in PLAYBOOK]
    if alert["type"].startswith("ANOMALY_"):
        keys = ["_ANOMALY"]
    return [step.format(ip=alert["ip"],
                        parent=d.get("parent_domain", ""),
                        scripts=", ".join(d.get("scripts", [])),
                        paths=", ".join(d.get("exposed_paths") or d.get("discovered_paths") or []) or "none",
                        users=", ".join(d.get("compromised_users", [])))
            for k in keys for step in PLAYBOOK[k]]


def is_breach(alert):
    """Evidence the attacker got in, not just tried."""
    d = alert["details"]
    return (alert["type"] == "SSH_LOGIN_AFTER_BRUTE_FORCE"
            or (alert["type"] == "WEB_LOGIN_BRUTE_FORCE" and d.get("successful_logins", 0) > 0)
            or (alert["type"] == "WEBSHELL" and d.get("command_requests", 0) > 0)
            # a matched reverse shell or log-wipe is executed attacker code, not just an attempt
            or alert["type"] in ("EDR_REVERSE_SHELL", "EDR_CLEAR_LOGS", "EDR_CREDENTIAL_ACCESS_FILES"))


def build_incidents(alerts):
    groups = defaultdict(list)
    for a in alerts:
        groups[a["ip"]].append(a)

    incidents = []
    for ip, group in groups.items():
        group.sort(key=lambda a: a["first_seen"])
        tactics = list(dict.fromkeys(a["mitre"]["tactic"] for a in group))
        breach = any(is_breach(a) for a in group)

        severity = max((a["severity"] for a in group), key=SEVERITIES.index)
        if len(tactics) >= 2:          # several attack stages from one source = escalate
            severity = raise_severity(severity)
        if breach:
            severity = "CRITICAL"

        timeline = sorted(
            ({**ev, "alert": a["title"]} for a in group for ev in a["evidence"]),
            key=lambda ev: ev["ts"],
        )
        if len(timeline) > MAX_TIMELINE:
            timeline = timeline[:MAX_TIMELINE - 10] + timeline[-10:]

        incidents.append({
            "ip":          ip,
            "severity":    severity,
            "breach":      breach,
            "first_seen":  group[0]["first_seen"],
            "last_seen":   max(a["last_seen"] for a in group),
            "tactics":     tactics,
            "techniques":  list(dict.fromkeys(a["mitre"]["technique_id"] for a in group)),
            "kill_chain":  " → ".join(f"{a['mitre']['tactic']} ({a['title']})" for a in group),
            "alert_ids":   [a["id"] for a in group],
            "timeline":    timeline,
            "response":    list(dict.fromkeys(step for a in group for step in _actions(a))),
        })

    incidents.sort(key=lambda i: (-SEVERITIES.index(i["severity"]), i["first_seen"]))
    return [{"id": f"INC-{n:03d}", **inc} for n, inc in enumerate(incidents, 1)]
