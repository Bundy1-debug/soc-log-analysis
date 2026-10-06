# SOC Log Analyzer — SSH Brute-Force Detection

A lightweight Python tool that parses Linux authentication logs (`auth.log`), flags IPs showing SSH brute-force behaviour, classifies their severity and produces a JSON report. It comes with a small Flask web interface for uploading and analysing a log file in the browser.

Built as a hands-on exercise in Tier-1 SOC analysis: simulate an attack in an isolated lab, collect the logs, then detect it.

---

## Features

| Feature | Details |
|---|---|
| Log parsing | Regex-based extraction of `Failed password`, `Invalid user` and `Accepted` events from `auth.log` |
| Brute-force detection | Flags any IP with **5 or more** failed attempts (configurable threshold) |
| Severity classification | 4 levels based on the number of failed attempts (see below) |
| Compromise indicator | Warns when a flagged IP also has a **successful login** in the log |
| Usernames tried | Lists the invalid usernames attempted by each flagged IP |
| Reports | Coloured terminal report + structured JSON output (`report_output.json`) |
| Web interface | Flask app: upload an `auth.log` or analyse the bundled sample, view results in a dashboard |

### Severity levels

| Severity | Failed attempts |
|---|---|
| CRITICAL | 100+ |
| HIGH | 30 – 99 |
| MEDIUM | 10 – 29 |
| LOW | 5 – 9 |

---

## Lab environment

| Role | Machine |
|---|---|
| Attacker | Kali Linux VM (Hydra) |
| Target | Ubuntu Server 22.04 VM (OpenSSH) |
| Network | Host-only adapter, fully isolated |
| Log source | `/var/log/auth.log` on the target |

All attack simulation was performed in this isolated lab, against machines I own.

---

## Installation

```bash
git clone https://github.com/Bundy1-debug/soc-log-analysis.git
cd soc-log-analysis
```

The command-line analyzer only uses the Python 3 standard library.
For the web interface:

```bash
pip install -r webapp/requirements.txt
```

---

## Usage

### Command line

```bash
# Analyse the bundled sample log
python3 src/log_analyzer.py sample_auth.log

# Analyse a real log (requires read access)
sudo python3 src/log_analyzer.py /var/log/auth.log
```

### Web interface

```bash
cd webapp
python3 app.py
```

Then open http://127.0.0.1:5000, upload an `auth.log` file or click the sample-analysis button.

---

## Sample output

Run on the included `sample_auth.log`:

```
============================================================
      SOC LOG ANALYZER — BRUTE FORCE DETECTION REPORT
============================================================
  Threshold : 5 failed attempts

  Total IPs with failed logins : 3
  Total failed attempts        : 21
  Successful logins            : 3
  Suspicious IPs flagged       : 2

  [1] 192.168.1.105
       Severity     : MEDIUM
       Failed tries : 12
       Users tried  : oracle
       ⚠ WARNING: Successful login detected from this IP!

  [2] 10.0.0.23
       Severity     : LOW
       Failed tries : 6
       Users tried  : postgres
============================================================
```

JSON report excerpt:

```json
{
  "summary": {
    "total_ips_with_failures": 3,
    "total_failed_attempts": 21,
    "total_successful_logins": 3,
    "flagged_ips": 2
  },
  "alerts": [
    {
      "ip": "192.168.1.105",
      "failed_count": 12,
      "users_tried": ["oracle"],
      "post_success": true,
      "severity": "MEDIUM"
    }
  ]
}
```

---

## Project structure

```
soc-log-analysis/
├── src/
│   └── log_analyzer.py      # CLI detection engine
├── webapp/
│   ├── app.py               # Flask web interface
│   ├── templates/index.html # Dashboard template
│   ├── requirements.txt
│   └── sample_auth.log
├── sample_auth.log          # Sample log (no real data)
├── report_output.json       # Example JSON report
├── Tools-used.txt
└── README.md
```

---

## Current limitations

- Detection is based on the **total** number of failures per IP; there is no time window yet.
- `post_success` means the IP has at least one successful login anywhere in the log; the order of events (before or after the failures) is not checked yet.
- Only SSH events from `auth.log` are supported.

## Roadmap

- [x] Web dashboard with Flask
- [ ] Time-window detection (e.g. N failures within 60 seconds)
- [ ] Order-aware compromise alert (success **after** the failures)
- [ ] MITRE ATT&CK mapping (T1110 — Brute Force)
- [ ] Equivalent Sigma rule, tested in a SIEM (Wazuh / ELK)
- [ ] IP geolocation and real-time mode (`tail -f`)

---

## Lessons learned

- Brute-force attacks generate hundreds of log lines: automation is essential.
- A successful login from an IP with many failures is a high-priority indicator of compromise.
- Threshold tuning is a trade-off between false positives and missed attacks.
- In production, this logic belongs in a SIEM correlated with other sources.

---

## Disclaimer

For educational purposes only. Only analyse logs and test systems you own or are explicitly authorised to assess.

## Author

**Haitham Daoudi** — Cybersecurity engineering student, ENSA Oujda
[LinkedIn](https://www.linkedin.com/in/haitham-daoudi) · [GitHub](https://github.com/Bundy1-debug)# 🔍 SOC Log Analyzer — SSH Brute Force Detection

> A lightweight Python-based Security Operations tool for detecting SSH brute force attacks by analyzing Linux authentication logs.

---

## 📌 Objective

Simulate and analyze a real SSH brute force attack scenario.  
The tool parses `/var/log/auth.log`, identifies suspicious IPs, classifies their threat severity, and generates a structured JSON report — mimicking the workflow of a Tier-1 SOC analyst.

---

## 🛠️ Tools Used

| Tool | Purpose |
|------|---------|
| Python 3 | Log parsing & detection engine |
| Hydra | Simulating the brute force attack (attacker side) |
| Kali Linux | Attack simulation environment |
| Ubuntu Server | Target machine (victim side) |
| `/var/log/auth.log` | Primary log source for analysis |

---

## 🧪 Methodology
Bundy1-debug
### Step 1 — Set up the lab

- Attacker machine: Kali Linux (VM)
- Target machine: Ubuntu Server (VM)
- Network: Host-only adapter (isolated)

### Step 2 — Simulate the attack

```bash
# On Kali Linux — launch SSH brute force with Hydra
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://TARGET_IP -t 4
```

> ⚠️ Only perform this in a controlled, isolated lab environment.

### Step 3 — Collect the logs

```bash
# On the Ubuntu target — view authentication logs
sudo cat /var/log/auth.log | grep "Failed password"
```

### Step 4 — Run the analyzer

```bash
# Clone the repo
git clone https://github.com/Bundy1-debug/soc-log-analysis.git
cd soc-log-analysis

# Run against real logs (requires sudo or log access)
python3 src/log_analyzer.py /var/log/auth.log

# OR use the included sample log for demo
python3 src/log_analyzer.py sample_auth.log
```

---

## 🔎 Findings

### What the tool detects

| Indicator | Description |
|-----------|-------------|
| `Failed password` | Multiple authentication failures from a single IP |
| `Invalid user` | Login attempts using non-existent usernames |
| Repeated attempts | Same IP appearing >5 times in a short window |
| Post-breach success | Successful login detected **after** brute force activity ⚠️ |

### Severity Classification

| Severity | Threshold |
|----------|-----------|
| 🔴 CRITICAL | 100+ failed attempts |
| 🟠 HIGH | 30–99 failed attempts |
| 🟡 MEDIUM | 10–29 failed attempts |
| 🔵 LOW | 5–9 failed attempts |

### Sample output (real run on `sample_auth.log`)

```
============================================================
      SOC LOG ANALYZER — BRUTE FORCE DETECTION REPORT
============================================================
  Generated : 2026-03-24 21:31:58
  Threshold : 5 failed attempts

  Total IPs with failed logins : 3
  Total failed attempts        : 21
  Successful logins            : 3
  Suspicious IPs flagged       : 2

  FLAGGED IPs
  ────────────────────────────────────────────────────────

  [1] 192.168.1.105
       Severity     : MEDIUM
       Failed tries : 12
       First seen   : Mar 20 10:01:22
       Last seen    : Mar 20 10:01:44
       Users tried  : oracle
       ⚠ WARNING: Successful login detected from this IP!

  [2] 10.0.0.23
       Severity     : LOW
       Failed tries : 6
       First seen   : Mar 20 10:05:01
       Last seen    : Mar 20 10:05:11
       Users tried  : postgres
============================================================
```

---

## 📁 Project Structure

```
soc-log-analysis/
│
├── README.md               # This file
├── sample_auth.log         # Sample log for demo (no real data)
├── report_output.json      # Auto-generated JSON report
├── Tools-used.txt          # Full tools list
│
├── src/
│   └── log_analyzer.py     # Main detection script
│
└── Screenshots/            # Lab environment screenshots
```

---

## 💡 Lessons Learned

- SSH brute force attacks generate **hundreds of log entries** — automation is essential for detection at scale
- A compromised login **after** repeated failures is a critical indicator of successful breach
- Threshold tuning matters: too low = false positives, too high = missed attacks
- Real SOC analysts combine log analysis with SIEM tools (Splunk, ELK) for this at scale
- Isolating attacker & victim in a host-only network is critical for safe lab work

---

## 🚀 Possible Improvements

- [ ] Add geolocation lookup per IP (using `ip-api.com`)
- [ ] Export report to PDF
- [ ] Add real-time monitoring mode (`tail -f`)
- [ ] Integrate with a SIEM (Splunk/ELK forwarding)
- [ ] Build a web dashboard with Flask

---


## 👤 Author

**[Daoudi Haitham]**  
Cybersecurity Student | Aspiring SOC Analyst  
[LinkedIn](https://www.linkedin.com/in/haitham-daoudi-905a34251/) · [GitHub](https://github.com/Bundy1-debug)
