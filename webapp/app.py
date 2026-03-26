# python3
"""
SOC Log Analyzer — Web App
Flask backend: handles file upload, runs analysis, returns JSON results
"""

from flask import Flask, render_template, request, jsonify
import re
import os
from collections import defaultdict
from datetime import datetime

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ─────────────────────────────────────────
# PATTERNS
# ─────────────────────────────────────────
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

FAILED_THRESHOLD = 5


# ─────────────────────────────────────────
# CORE LOGIC (same as CLI tool)
# ─────────────────────────────────────────
def parse_log(content: str) -> dict:
    failed_attempts   = defaultdict(list)
    invalid_users     = defaultdict(list)
    successful_logins = defaultdict(list)

    for line in content.splitlines():
        m = PATTERNS["failed_password"].search(line)
        if m:
            ts, ip = m.group(1), m.group(2)
            failed_attempts[ip].append(ts)
            continue

        m = PATTERNS["invalid_user"].search(line)
        if m:
            ts, user, ip = m.group(1), m.group(2), m.group(3)
            invalid_users[ip].append(user)
            continue

        m = PATTERNS["accepted"].search(line)
        if m:
            ts, ip = m.group(1), m.group(2)
            successful_logins[ip].append(ts)

    return {
        "failed_attempts":   dict(failed_attempts),
        "invalid_users":     dict(invalid_users),
        "successful_logins": dict(successful_logins),
    }


def classify_severity(count: int) -> str:
    if count >= 100: return "CRITICAL"
    if count >= 30:  return "HIGH"
    if count >= 10:  return "MEDIUM"
    return "LOW"


def detect_brute_force(data: dict) -> list:
    alerts = []
    for ip, timestamps in data["failed_attempts"].items():
        count = len(timestamps)
        if count >= FAILED_THRESHOLD:
            alerts.append({
                "ip":           ip,
                "failed_count": count,
                "first_seen":   timestamps[0],
                "last_seen":    timestamps[-1],
                "users_tried":  list(set(data["invalid_users"].get(ip, []))),
                "post_success": ip in data["successful_logins"],
                "severity":     classify_severity(count),
            })
    return sorted(alerts, key=lambda x: x["failed_count"], reverse=True)


def analyze(content: str) -> dict:
    data   = parse_log(content)
    alerts = detect_brute_force(data)

    # Build chart data: top 10 IPs by attempt count
    top_ips = sorted(
        data["failed_attempts"].items(),
        key=lambda x: len(x[1]),
        reverse=True
    )[:10]

    # Severity counts for pie chart
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for a in alerts:
        severity_counts[a["severity"]] += 1

    return {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "summary": {
            "total_ips":       len(data["failed_attempts"]),
            "total_failures":  sum(len(v) for v in data["failed_attempts"].values()),
            "total_successes": sum(len(v) for v in data["successful_logins"].values()),
            "flagged_ips":     len(alerts),
            "breaches":        sum(1 for a in alerts if a["post_success"]),
        },
        "alerts":          alerts,
        "chart_ips":       [ip for ip, _ in top_ips],
        "chart_counts":    [len(ts) for _, ts in top_ips],
        "severity_counts": severity_counts,
    }


# ─────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze_route():
    if "logfile" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["logfile"]
    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    try:
        content = file.read().decode("utf-8", errors="replace")
        result  = analyze(content)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/analyze-sample", methods=["POST"])
def analyze_sample():
    """Run analysis on the built-in sample log"""
    sample = open("sample_auth.log").read() if os.path.exists("sample_auth.log") else SAMPLE_LOG
    result = analyze(sample)
    return jsonify(result)


SAMPLE_LOG = """Mar 20 10:01:22 ubuntu sshd[1100]: Failed password for root from 192.168.1.105 port 45231 ssh2
Mar 20 10:01:24 ubuntu sshd[1101]: Failed password for root from 192.168.1.105 port 45232 ssh2
Mar 20 10:01:26 ubuntu sshd[1102]: Failed password for admin from 192.168.1.105 port 45233 ssh2
Mar 20 10:01:28 ubuntu sshd[1103]: Invalid user oracle from 192.168.1.105 port 45234
Mar 20 10:01:28 ubuntu sshd[1103]: Failed password for invalid user oracle from 192.168.1.105 port 45234 ssh2
Mar 20 10:01:30 ubuntu sshd[1104]: Failed password for root from 192.168.1.105 port 45235 ssh2
Mar 20 10:01:32 ubuntu sshd[1105]: Failed password for ubuntu from 192.168.1.105 port 45236 ssh2
Mar 20 10:01:34 ubuntu sshd[1106]: Failed password for root from 192.168.1.105 port 45237 ssh2
Mar 20 10:01:36 ubuntu sshd[1107]: Failed password for pi from 192.168.1.105 port 45238 ssh2
Mar 20 10:01:38 ubuntu sshd[1108]: Failed password for root from 192.168.1.105 port 45239 ssh2
Mar 20 10:01:40 ubuntu sshd[1109]: Failed password for root from 192.168.1.105 port 45240 ssh2
Mar 20 10:01:42 ubuntu sshd[1110]: Failed password for root from 192.168.1.105 port 45241 ssh2
Mar 20 10:01:44 ubuntu sshd[1111]: Failed password for root from 192.168.1.105 port 45242 ssh2
Mar 20 10:01:44 ubuntu sshd[1111]: Accepted password for root from 192.168.1.105 port 45242 ssh2
Mar 20 10:05:01 ubuntu sshd[1200]: Failed password for root from 10.0.0.23 port 55001 ssh2
Mar 20 10:05:03 ubuntu sshd[1201]: Failed password for admin from 10.0.0.23 port 55002 ssh2
Mar 20 10:05:05 ubuntu sshd[1202]: Failed password for test from 10.0.0.23 port 55003 ssh2
Mar 20 10:05:07 ubuntu sshd[1203]: Invalid user postgres from 10.0.0.23 port 55004
Mar 20 10:05:07 ubuntu sshd[1203]: Failed password for invalid user postgres from 10.0.0.23 port 55004 ssh2
Mar 20 10:05:09 ubuntu sshd[1204]: Failed password for root from 10.0.0.23 port 55005 ssh2
Mar 20 10:05:11 ubuntu sshd[1205]: Failed password for root from 10.0.0.23 port 55006 ssh2
Mar 20 10:20:00 ubuntu sshd[1300]: Failed password for vagrant from 172.16.5.50 port 60001 ssh2
Mar 20 10:20:02 ubuntu sshd[1301]: Failed password for vagrant from 172.16.5.50 port 60002 ssh2
Mar 20 10:20:04 ubuntu sshd[1302]: Failed password for vagrant from 172.16.5.50 port 60003 ssh2
Mar 20 10:30:00 ubuntu sshd[1400]: Accepted password for alice from 192.168.1.10 port 22111 ssh2"""


if __name__ == "__main__":
    	app.run(debug=True, port=5000)
