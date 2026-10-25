"""
SOC Log Analyzer — Flask web dashboard.
All detection logic lives in soc_analyzer/; this file only handles HTTP.

Run:  python3 webapp/app.py            (http://127.0.0.1:5000)
Env:  FLASK_DEBUG=1      enable the debugger (local development only — it allows code execution)
      SOC_DISABLE_GEO=1  do not send IPs to ip-api.com
"""

import ipaddress
import logging
import os
import sys
from pathlib import Path

from flask import Flask, jsonify, render_template, request

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))                       # make soc_analyzer importable

from soc_analyzer import analyze                    # noqa: E402
from soc_analyzer.geo import geolocate              # noqa: E402

SAMPLE_LOG = ROOT / "sample_auth.log"
SAMPLE_DIR = ROOT / "samples"                       # one log per detection pack
GEO_ENABLED = os.environ.get("SOC_DISABLE_GEO") != "1"

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024 * 1024    # 32 MB upload limit
log = logging.getLogger(__name__)

# Log content is attacker-controlled. The page escapes it, and this policy is a second
# layer: even if some markup slipped through, inline scripts would not run.
CSP = ("default-src 'self'; "
       "script-src 'self' https://cdn.jsdelivr.net; "
       "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
       "font-src https://fonts.gstatic.com; "
       "img-src 'self' data:; "
       "connect-src 'self'; "
       "frame-ancestors 'none'; base-uri 'none'; form-action 'self'")


@app.after_request
def security_headers(resp):
    resp.headers["Content-Security-Policy"] = CSP
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


def run_analysis(lines, sources):
    try:
        return jsonify(analyze(lines, sources=sources, geo=GEO_ENABLED))
    except Exception:
        log.exception("analysis failed")
        return jsonify({"error": "Analysis failed — check the server log"}), 500   # no internals to the client


# ── Routes ───────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze_route():
    files = [f for f in request.files.getlist("logfile") if f.filename]
    if not files:
        return jsonify({"error": "No file selected"}), 400
    lines = []
    for f in files:
        lines.extend(f.read().decode("utf-8", errors="replace").splitlines())
    return run_analysis(lines, [f.filename for f in files])


@app.route("/analyze-sample", methods=["POST"])
def analyze_sample():
    paths = [p for p in [SAMPLE_LOG, *sorted(SAMPLE_DIR.glob("*.log"))] if p.exists()]
    if not paths:
        return jsonify({"error": "Sample log not found"}), 404
    lines = [line for p in paths for line in p.read_text(errors="replace").splitlines()]
    return run_analysis(lines, [p.name for p in paths])


@app.route("/geoip/<ip>")
def geoip(ip):
    try:
        ip = str(ipaddress.ip_address(ip))
    except ValueError:
        return jsonify({"error": "Invalid IP address"}), 400
    if not GEO_ENABLED:
        return jsonify({"error": "Geolocation disabled"}), 403
    return jsonify(geolocate([ip]).get(ip, {"country": "Unknown", "countryCode": "??"}))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=os.environ.get("FLASK_DEBUG") == "1")
