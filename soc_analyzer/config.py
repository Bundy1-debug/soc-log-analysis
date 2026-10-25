"""
Detection tuning.
Every threshold here is a trade-off: lower = more alerts (and false positives),
higher = fewer alerts (and missed attacks).
"""

from pathlib import Path

# ── SSH ──────────────────────────────────────────────────────────
SSH_FAIL_THRESHOLD     = 5      # failed logins ...
SSH_WINDOW_SECONDS     = 60     # ... inside this sliding window = brute force
SPRAY_MIN_USERS        = 5      # distinct usernames before we call it password spraying
SPRAY_MAX_PER_USER     = 2      # spraying = many users, few tries each
BREACH_LOOKBACK_HOURS  = 24     # a success counts as a breach if the failures happened within this time before it

# ── HTTP ─────────────────────────────────────────────────────────
HTTP_THRESHOLD         = 3      # suspicious requests ...
HTTP_WINDOW_SECONDS    = 300    # ... inside this window = scan

WEB_LOGIN_THRESHOLD    = 10     # failed login POSTs ...
WEB_LOGIN_WINDOW_SECONDS = 60   # ... inside this window = web brute force
DIRBUST_THRESHOLD      = 30     # 404s ...
DIRBUST_WINDOW_SECONDS = 60     # ... inside this window = wordlist scan
WEBSHELL_MIN_POSTS     = 3      # POSTs to a script in an upload folder
HTTP_LARGE_RESPONSE_BYTES = 50 * 1024 * 1024    # one response this big is unusual for a web app
HTTP_LARGE_TOTAL_BYTES    = 500 * 1024 * 1024   # total served to one IP

# ── Host / privilege (auth.log) ──────────────────────────────────
SUDO_FAIL_THRESHOLD    = 3      # failed sudo attempts by one user ...
SUDO_WINDOW_SECONDS    = 120    # ... inside this window = sudo brute force / probing
SU_FAIL_THRESHOLD      = 3      # failed `su` attempts by one user in the same window

# ── EDR-style host commands (auditd) ─────────────────────────────
# One matching command is enough to alert; see soc_analyzer/detections_edr.py for the rules.

# ── DNS ──────────────────────────────────────────────────────────
DNS_THRESHOLD          = 1      # any suspicious lookup is worth an alert
DGA_MIN_LENGTH         = 12     # labels shorter than this are never called DGA
DGA_ENTROPY            = 3.5    # Shannon entropy (bits/char) above which a label looks random

# DNS tunneling / exfiltration (per internal host + parent domain)
TUNNEL_MIN_QUERIES     = 10     # fewer lookups than this are never called tunneling
TUNNEL_MIN_UNIQUE      = 20     # distinct subdomains under one parent domain
TUNNEL_LONG_LABEL      = 40     # a label this long is unusual (the DNS maximum is 63)
TUNNEL_LONG_QUERY      = 60     # total subdomain length that is unusual
TUNNEL_TXT_RATIO       = 0.5    # share of TXT/NULL queries that is unusual

# C2 beaconing (per internal host + parent domain)
BEACON_MIN_QUERIES     = 8      # need this many lookups to judge regularity
BEACON_MIN_INTERVAL    = 10     # seconds; faster than this is a burst, not a beacon
BEACON_MAX_JITTER      = 0.2    # stdev / mean of the intervals; 0 = perfectly regular

# Parent domains with legitimately many subdomains or periodic lookups (CDNs, AV, time, updates)
DNS_ALLOWLIST          = {"ntp.org", "ubuntu.com", "microsoft.com", "windowsupdate.com",
                          "akamaiedge.net", "cloudfront.net", "amazonaws.com", "googleapis.com"}

# ── Severity by event count (CRITICAL, HIGH, MEDIUM) ─────────────
SSH_SEVERITY           = (100, 30, 10)
HTTP_SEVERITY          = (50, 20, 5)
DNS_SEVERITY           = (20, 10, 3)

# ── Context ──────────────────────────────────────────────────────
# Trusted sources that must never raise alerts (e.g. your admin jump host, a vuln scanner you run).
ALLOWLIST_IPS          = set()

INTEL_DIR              = Path(__file__).resolve().parent.parent / "intel"
MAX_EVIDENCE           = 25     # raw events kept per alert
