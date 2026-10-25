# 🔍 SOC Log Analyzer — Multi-Source Threat Detection

> A Python detection engine that parses Linux SSH, web server and DNS logs, detects attacks with time-window rules, maps them to **MITRE ATT&CK**, and correlates them into **incidents with a timeline and a response playbook** — from the terminal or a web dashboard.

---

## 📌 Objective

Simulate real attacks in an isolated lab and build the tool a Tier-1 SOC analyst needs to triage them:
**collect → parse → detect → enrich → correlate → respond**.

---

## 🔎 What it detects

| Detection | Log source | Logic | MITRE ATT&CK |
|---|---|---|---|
| SSH brute force | `auth.log` | ≥ 5 failures from one IP inside a 60 s sliding window | T1110.001 Password Guessing |
| SSH password spraying | `auth.log` | ≥ 5 accounts, ≤ 2 tries each | T1110.003 Password Spraying |
| **Login after brute force** | `auth.log` | Any `Accepted <method>` preceded by a brute force from the same IP (24 h) → always **CRITICAL** | T1078 Valid Accounts |
| Web vulnerability scan | Apache/Nginx access log | Sensitive paths, scanner user agents (sqlmap, nikto…) in a 5 min window | T1595.002 Vulnerability Scanning |
| Web exploitation | Apache/Nginx access log | SQL injection, XSS, path traversal, command injection payloads (URL-decoded) | T1190 Exploit Public-Facing App |
| Secret exposure | Apache/Nginx access log | `/.env`, `/.git`, backups… answered **2xx** → severity raised | — |
| More exploit signatures | Apache/Nginx access log | Log4Shell, Shellshock, file inclusion (LFI/RFI), SSRF — in the URL **or the User-Agent** | T1190 |
| **Web login brute force** | Apache/Nginx access log | ≥ 10 failed login POSTs in 60 s; a 302 afterwards = login succeeded → **breach** | T1110.001 / T1078 |
| Directory brute force | Apache/Nginx access log | ≥ 30 × 404 in 60 s (gobuster, dirb); lists the paths that answered | T1595.003 Wordlist Scanning |
| **Webshell** | Apache/Nginx access log | Successful requests to a script with `?cmd=`-style parameters, or repeated POSTs to a script in an upload folder → command use = **breach** | T1505.003 Web Shell |
| Large data transfer | Apache/Nginx access log | One response ≥ 50 MB or ≥ 500 MB total to one IP; data files (.sql, .bak, .zip) raise severity; .iso etc. are expected | T1041 |
| Suspicious DNS | BIND query log | Threat-intel domain match, malware keywords (whole words), suspicious TLD + another signal | T1071.004 DNS |
| DGA domains | BIND query log | Long, high-entropy labels (Shannon entropy ≥ 3.5) | T1568.002 Domain Generation Algorithms |
| **DNS tunneling / exfiltration** | BIND query log | Per host + parent domain: ≥ 2 of many unique subdomains, long labels, encoded (hex/base32/base64) labels, TXT/NULL-heavy; estimates KB carried | T1048.003 Exfiltration Over Alternative Protocol |
| **C2 beaconing** | BIND query log | ≥ 8 lookups of one domain at regular intervals (jitter ≤ 20 %, interval ≥ 10 s) | T1071.004 DNS |
| Sudo abuse | `auth.log` | Repeated failed sudo, or any "user NOT in sudoers" (per user) | T1548.003 Sudo |
| Su brute force | `auth.log` | ≥ 3 failed `su` attempts by one user | T1548.003 |
| **New account created** | `auth.log` | `useradd` added a local account | T1136.001 Local Account |
| **Privileged group grant** | `auth.log` | A user added to `sudo`/`root`/`wheel`/`admin` | T1098 Account Manipulation |
| **Reverse shell** (EDR) | `auditd` exec | `/dev/tcp`, `nc -e`, `bash -i`, python pty spawn | T1059.004 Unix Shell |
| **Download-and-run** (EDR) | `auditd` exec | `curl\|bash`, running from `/tmp`, `chmod +x /tmp/…` | T1105 Ingress Tool Transfer |
| **Credential access** (EDR) | `auditd` exec | Reading `/etc/shadow`, SSH/cloud private keys | T1003.008 / T1552.004 |
| **Persistence** (EDR) | `auditd` exec | crontab, `authorized_keys`, systemd/init changes | T1053.003 / T1098.004 / T1543.002 |
| **Defense evasion** (EDR) | `auditd` exec | Clearing `/var/log`, `history -c`, unsetting HISTFILE | T1070.002 / T1070.003 |

**Correlation:** all alerts from one IP become one incident. An incident spanning several ATT&CK tactics is escalated one level; a breach is always CRITICAL. Each incident gets a merged timeline and recommended response steps.

**Enrichment:** local threat-intel IOC lists (`intel/`), optional IP geolocation (ip-api.com).

**Parsing:** classic and RFC 3339 syslog timestamps, rsyslog `message repeated N times`, IPv4 + IPv6, `sshd` and `sshd-session`, real BIND `client IP#port` format, year inference for year-less syslog lines.

---

## 🏗️ Architecture

```
src/log_analyzer.py ─┐                     (CLI: terminal + JSON)
                     ├──► soc_analyzer.analyze(lines)
webapp/app.py ───────┘                     (Flask dashboard)

soc_analyzer/
├── parsers.py       raw lines → normalized Event objects
├── detections.py    SSH + core web rules → alerts (severity, ATT&CK, evidence)
├── detections_web.py  login/dir brute force, webshell, large transfer
├── detections_dns.py  DNS tunneling / exfiltration, C2 beaconing
├── detections_host.py sudo/su abuse, new accounts, privilege grants
├── detections_edr.py  auditd command rules: reverse shell, persistence, log wiping
├── intel.py         IOC blocklists from intel/
├── mitre.py         ATT&CK technique / tactic table
├── correlation.py   alerts → incidents (timeline + response playbook)
├── engine.py        runs the pipeline, builds the report
├── report.py        terminal output
├── geo.py           optional IP geolocation
└── config.py        every threshold, window and the allowlist
```

One engine, two interfaces: the CLI and the dashboard can never disagree.

---

## 🚀 Usage

```bash
git clone https://github.com/Bundy1-debug/soc-log-analysis.git
cd soc-log-analysis

# CLI — no dependencies needed
python3 src/log_analyzer.py sample_auth.log
python3 src/log_analyzer.py sample_auth.log samples/*.log      # all detection packs
python3 src/log_analyzer.py /var/log/auth.log /var/log/apache2/access.log -o report.json
python3 src/log_analyzer.py --help

# Web dashboard
python3 -m venv .venv && source .venv/bin/activate
pip install -r webapp/requirements.txt
python3 webapp/app.py            # → http://127.0.0.1:5000
#   SOC_DISABLE_GEO=1  → never send IPs to the geolocation API
#   FLASK_DEBUG=1      → debugger (local development only)

# Tests
pip install -r requirements-dev.txt
pytest
```

### Sample output (`sample_auth.log`, abridged)

```
  Incidents  : 5    Alerts : 11    Breaches : 1
  Severity   : CRITICAL 2  HIGH 3  MEDIUM 2  LOW 4

  [INC-001] 192.168.1.105  [CRITICAL]  ⚠ BREACH
    Kill chain : Credential Access (SSH brute force) → Initial Access (Successful SSH login
                 after brute force) → Reconnaissance (Web vulnerability scan) → Command and
                 Control (Suspicious DNS lookups)
    ATT&CK     : T1110.001, T1078, T1595.002, T1071.004
    • CRITICAL Successful SSH login after brute force: Logged in as root after 12 failed attempts
    • HIGH     Web vulnerability scan: 5 suspicious web requests; 1 sensitive file(s) answered 2xx
    • HIGH     Suspicious DNS lookups: 1 lookup(s) of suspicious domains (known-bad per threat intel)
    • MEDIUM   SSH brute force: 12 failed SSH logins (peak 12 in 60s) against 5 account(s)
        accounts: root(8), admin(1), oracle(1), ubuntu(1), pi(1)
    Response:
      1. Block 192.168.1.105 at the firewall (or let fail2ban ban it)
      3. Treat the host as compromised: isolate it from the network
      4. Reset the password of root and kill their active sessions
      ...
```

---

## 🧪 Lab methodology

| Tool | Purpose |
|------|---------|
| Kali Linux (VM) | Attacker |
| Ubuntu Server (VM) | Target — OpenSSH, Apache, BIND |
| Hydra | SSH brute force simulation |
| Host-only network | Isolation between VMs |

```bash
# On Kali — SSH brute force against the lab target only
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://TARGET_IP -t 4

# On the Ubuntu target — collect the evidence
sudo cp /var/log/auth.log ~/evidence/
```

> ⚠️ Only perform attacks in a controlled, isolated lab environment.

---

## 🔐 Security of the tool itself

Log lines are written by attackers, so the dashboard treats them as hostile:

- **No `innerHTML` with data** — every value is rendered with `textContent` (a malicious user agent like `<img src=x onerror=…>` is shown as text, never executed). A test enforces this.
- **Content-Security-Policy** blocks inline scripts as a second layer; Chart.js is pinned with Subresource Integrity.
- Flask **debug mode is off** by default (the Werkzeug debugger allows remote code execution) and the app binds to `127.0.0.1`.
- Errors are logged server-side; clients get a generic message. `/geoip/<ip>` validates its input.

---

## 🎛️ Tuning and false positives

All thresholds live in `soc_analyzer/config.py`. Main levers:

- `SSH_FAIL_THRESHOLD` / `SSH_WINDOW_SECONDS` — sensitivity vs. noise
- `ALLOWLIST_IPS` — your own admin hosts and authorized scanners
- `intel/bad_ips.txt`, `intel/bad_domains.txt` — IOC feeds (demo entries; replace with a real feed)
- Scripted clients (`curl`, `python-requests`) are context, not alerts on their own; a suspicious TLD alone never alerts

## ⚠️ Known limitations

- Batch analysis of files (no real-time `tail -f` mode yet)
- Correlation is by IP (network logs) or by user (host logs), not across the two yet
- auditd detection reads the **command line** (EXECVE); it does not yet correlate PATH/open syscalls, so file reads done without a shell command are not seen
- Timezones are dropped: syslog has none, so all times are compared as wall-clock
- Low-and-slow attacks below the window threshold are not detected

## 🗺️ Roadmap

- [ ] Real-time mode with automatic blocking (fail2ban-style)
- [ ] Export detections as Sigma rules
- [ ] Ship alerts to Elastic/Splunk (ECS JSON)
- [ ] AbuseIPDB reputation lookup
- [ ] Docker image

---

## ⚠️ Disclaimer

This project is for **educational purposes only**.
All attack simulations were performed in an **isolated, controlled lab environment**.
Never run brute force tools against systems you do not own or have explicit permission to test.

---

## 👤 Author

**[Daoudi Haitham]**
Cybersecurity Student | Aspiring SOC Analyst
[LinkedIn](https://www.linkedin.com/in/haitham-daoudi-905a34251/) · [GitHub](https://github.com/Bundy1-debug)
