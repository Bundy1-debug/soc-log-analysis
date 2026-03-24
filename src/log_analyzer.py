#!/usr/bin/env python3
"""
SOC Log Analyzer - Brute Force Detection Tool
Author: [Your Name]
Description: Analyzes /var/log/auth.log to detect SSH brute force attacks
"""

import re
import sys
import json
from collections import defaultdict
from datetime import datetime


# ──────────────────────────────────────────────
# CONFIG
# ──────────────────────────────────────────────
FAILED_THRESHOLD = 5          # attempts before flagging an IP
LOG_FILE         = "/var/log/auth.log"
OUTPUT_JSON      = "report_output.json"

# Regex patterns
PATTERNS = {
    "failed_password": re.compile(
        r"(\w{3}\s+\d+\s[\d:]+).*Failed password.*from\s([\d.]+)"
    ),
    "invalid_user": re.compile(
        r"(\w{3}\s+\d+\s[\d:]+).*Invalid user\s(\S+)\sfrom\s([\d.]+)"
    ),
    "accepted": re.compile(
        r"(\w{3}\s+\d+\s[\d:]+).*Accepted password.*from\s([\d.]+)"
    ),
}


# ──────────────────────────────────────────────
# PARSER
# ──────────────────────────────────────────────
def parse_log(filepath: str) -> dict:
    """Parse auth.log and return structured event data."""
    failed_attempts  = defaultdict(list)   # ip -> [timestamps]
    invalid_users    = defaultdict(list)   # ip -> [usernames tried]
    successful_logins = defaultdict(list)  # ip -> [timestamps]

    try:
        with open(filepath, "r", errors="replace") as f:
            for line in f:
                # Failed password
                m = PATTERNS["failed_password"].search(line)
                if m:
                    ts, ip = m.group(1), m.group(2)
                    failed_attempts[ip].append(ts)
                    continue

                # Invalid user
                m = PATTERNS["invalid_user"].search(line)
                if m:
                    ts, user, ip = m.group(1), m.group(2), m.group(3)
                    invalid_users[ip].append(user)
                    continue

                # Successful login
                m = PATTERNS["accepted"].search(line)
                if m:
                    ts, ip = m.group(1), m.group(2)
                    successful_logins[ip].append(ts)

    except FileNotFoundError:
        print(f"[ERROR] Log file not found: {filepath}")
        sys.exit(1)

    return {
        "failed_attempts":   dict(failed_attempts),
        "invalid_users":     dict(invalid_users),
        "successful_logins": dict(successful_logins),
    }


# ──────────────────────────────────────────────
# DETECTION ENGINE
# ──────────────────────────────────────────────
def detect_brute_force(data: dict, threshold: int = FAILED_THRESHOLD) -> list:
    """Flag IPs exceeding the failed-attempt threshold."""
    alerts = []
    for ip, timestamps in data["failed_attempts"].items():
        count = len(timestamps)
        if count >= threshold:
            alert = {
                "ip":            ip,
                "failed_count":  count,
                "first_seen":    timestamps[0],
                "last_seen":     timestamps[-1],
                "users_tried":   list(set(data["invalid_users"].get(ip, []))),
                "post_success":  ip in data["successful_logins"],
                "severity":      classify_severity(count),
            }
            alerts.append(alert)

    # Sort by count descending
    return sorted(alerts, key=lambda x: x["failed_count"], reverse=True)


def classify_severity(count: int) -> str:
    if count >= 100:
        return "CRITICAL"
    elif count >= 30:
        return "HIGH"
    elif count >= 10:
        return "MEDIUM"
    return "LOW"


# ──────────────────────────────────────────────
# REPORT
# ──────────────────────────────────────────────
COLORS = {
    "CRITICAL": "\033[91m",
    "HIGH":     "\033[31m",
    "MEDIUM":   "\033[33m",
    "LOW":      "\033[34m",
    "RESET":    "\033[0m",
    "BOLD":     "\033[1m",
    "GREEN":    "\033[92m",
    "CYAN":     "\033[96m",
}

def c(color: str, text: str) -> str:
    return f"{COLORS.get(color,'')}{text}{COLORS['RESET']}"


def print_report(alerts: list, data: dict) -> None:
    print()
    print(c("BOLD", "=" * 60))
    print(c("BOLD", "      SOC LOG ANALYZER — BRUTE FORCE DETECTION REPORT"))
    print(c("BOLD", "=" * 60))
    print(f"  Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Log file  : {LOG_FILE}")
    print(f"  Threshold : {FAILED_THRESHOLD} failed attempts")
    print(c("BOLD", "-" * 60))

    total_ips   = len(data["failed_attempts"])
    total_fails = sum(len(v) for v in data["failed_attempts"].values())
    total_ok    = sum(len(v) for v in data["successful_logins"].values())

    print(f"\n  {c('CYAN','Total IPs with failed logins :')} {total_ips}")
    print(f"  {c('CYAN','Total failed attempts        :')} {total_fails}")
    print(f"  {c('GREEN','Successful logins            :')} {total_ok}")
    print(f"  {c('BOLD','Suspicious IPs flagged       :')} {len(alerts)}")

    if not alerts:
        print(f"\n  {c('GREEN','✔ No brute force activity detected.')}\n")
        return

    print(f"\n{c('BOLD','  FLAGGED IPs')}")
    print(c("BOLD", "  " + "-" * 56))

    for i, alert in enumerate(alerts, 1):
        sev_color = alert["severity"]
        print(f"\n  [{i}] {c('BOLD', alert['ip'])}")
        print(f"       Severity     : {c(sev_color, alert['severity'])}")
        print(f"       Failed tries : {alert['failed_count']}")
        print(f"       First seen   : {alert['first_seen']}")
        print(f"       Last seen    : {alert['last_seen']}")
        if alert["users_tried"]:
            users = ", ".join(alert["users_tried"][:5])
            if len(alert["users_tried"]) > 5:
                users += f" (+{len(alert['users_tried'])-5} more)"
            print(f"       Users tried  : {users}")
        if alert["post_success"]:
            print(f"       {c('CRITICAL','⚠ WARNING: Successful login detected from this IP!')}")

    print()
    print(c("BOLD", "=" * 60))


def save_json(alerts: list, data: dict, path: str) -> None:
    output = {
        "generated_at":    datetime.now().isoformat(),
        "summary": {
            "total_ips_with_failures": len(data["failed_attempts"]),
            "total_failed_attempts":   sum(len(v) for v in data["failed_attempts"].values()),
            "total_successful_logins": sum(len(v) for v in data["successful_logins"].values()),
            "flagged_ips":             len(alerts),
        },
        "alerts": alerts,
    }
    with open(path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"  [+] JSON report saved → {path}\n")


# ──────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────
def main():
    log_path = sys.argv[1] if len(sys.argv) > 1 else LOG_FILE
    print(f"\n[*] Parsing log file: {log_path}")

    data   = parse_log(log_path)
    alerts = detect_brute_force(data)

    print_report(alerts, data)
    save_json(alerts, data, OUTPUT_JSON)


if __name__ == "__main__":
    main()
