"""
Generate samples/anomaly_baseline.log — fake data with a baseline, for Pack 5.

Signature rules find nothing here: every request is a normal 200 and every domain is ordinary.
Only the statistical detectors fire, because there is enough history to compare against.

  08:00–10:48 (baseline)  8 known IPs browsing, known domains looked up
  11:00–11:30 (recent)    198.51.100.231 — a NEW IP — makes 60 normal requests  -> volume outlier + new source
                          192.168.1.40 looks up 4 domains never seen before      -> new domains
"""

import random
from datetime import datetime, timedelta
from pathlib import Path

random.seed(23)
http, dns = [], []
BROWSER = "Mozilla/5.0 (X11; Linux x86_64) Firefox/124.0"
t0 = datetime(2024, 4, 2, 8, 0, 0)


def web(ts, ip, path="/"):
    http.append((ts, f'{ip} - - [{ts:%d/%b/%Y:%H:%M:%S} +0000] "GET {path} HTTP/1.1" 200 2500 "-" "{BROWSER}"'))


def query(ts, ip, domain):
    dns.append((ts, f"{ts:%b %d %H:%M:%S} ubuntu named[3000]: client @0x7f {ip}#40000 "
                    f"({domain}): query: {domain} IN A +E(0)K (10.0.0.1)"))


baseline_ips = [f"203.0.113.{n}" for n in range(10, 18)]          # 8 known sources
baseline_domains = ["www.company.com", "mail.company.com", "intranet.company.com",
                    "www.google.com", "github.com", "fonts.gstatic.com"]
internal = [f"192.168.1.{n}" for n in range(10, 16)]

# Baseline: ~2h45m of steady, modest activity
for minute in range(0, 168, 2):
    ts = t0 + timedelta(minutes=minute)
    web(ts, random.choice(baseline_ips), random.choice(["/", "/about", "/products", "/blog"]))
    query(ts + timedelta(seconds=10), random.choice(internal), random.choice(baseline_domains))

# Recent: a brand-new IP bursts 60 normal requests (volume outlier + first-seen source)
burst = datetime(2024, 4, 2, 11, 0, 0)
for i in range(60):
    web(burst + timedelta(seconds=i * 20), "198.51.100.231", random.choice(["/", "/login", "/account"]))

# Recent: an internal host looks up domains never seen before
for i, dom in enumerate(["telemetry.unknown-xyz.io", "cdn.newthing.io", "api.newthing.io", "track.newthing.io"]):
    query(burst + timedelta(minutes=5, seconds=i * 30), "192.168.1.40", dom)

rows = sorted(http + dns, key=lambda x: x[0])
out = Path(__file__).resolve().parent / "anomaly_baseline.log"
out.write_text("\n".join(line for _, line in rows) + "\n")
print(f"wrote {len(rows)} lines to {out}")
