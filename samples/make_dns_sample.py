"""
Generate samples/dns_exfil_c2.log — fake lab data for the DNS tunneling and beaconing detections.

  192.168.1.77  hex-encoded fake text in TXT lookup subdomains   → DNS tunneling
  192.168.1.88  one lookup every 60 s (±1 s)                      → C2 beaconing
  192.168.1.10  normal browsing + allowlisted CDN hostnames      → must stay quiet
"""

import random
from datetime import datetime, timedelta
from pathlib import Path

random.seed(7)
lines = []


def q(ts, client, domain, qtype="A"):
    lines.append(f"{ts:%b %d %H:%M:%S} ubuntu named[3000]: client @0x7f3a2c {client}#{random.randint(30000, 60000)} "
                 f"({domain}): query: {domain} IN {qtype} +E(0)K (10.0.0.1)")


t0 = datetime(2024, 3, 20, 12, 0, 0)

secret = ("LAB-ONLY fake customer export: id,name,card ; 1,alice,XXXX ; 2,bob,XXXX ; " * 12).encode().hex()
chunks = [secret[i:i + 48] for i in range(0, len(secret), 48)]
for n, chunk in enumerate(chunks):
    q(t0 + timedelta(seconds=n * 2), "192.168.1.77", f"{chunk}.{n}.t.exfil-lab.xyz", "TXT")

for n in range(12):
    q(t0 + timedelta(seconds=n * 60 + random.uniform(-1, 1)), "192.168.1.88", "updates.beacon-lab.net")

for n in range(15):
    q(t0 + timedelta(seconds=random.randint(0, 900)), "192.168.1.10",
      random.choice(["www.google.com", "github.com", "fonts.gstatic.com", "api.github.com"]))
for n in range(25):
    q(t0 + timedelta(seconds=n * 7), "192.168.1.10", f"d{random.getrandbits(48):x}.cloudfront.net")

lines.sort(key=lambda line: datetime.strptime("2024 " + line[:15], "%Y %b %d %H:%M:%S"))
out = Path(__file__).resolve().parent / "dns_exfil_c2.log"
out.write_text("\n".join(lines) + "\n")
print(f"wrote {len(lines)} lines to {out}")
