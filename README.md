# 🔍 SOC Log Analyzer — SSH Brute Force Detection

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
git clone https://github.com/YOUR_USERNAME/soc-log-analysis.git
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

## ⚠️ Disclaimer

This project is for **educational purposes only**.  
All attack simulations were performed in an **isolated, controlled lab environment**.  
Never run brute force tools against systems you do not own or have explicit permission to test.

---

## 👤 Author

**[Your Name]**  
Cybersecurity Student | Aspiring SOC Analyst  
[LinkedIn](https://linkedin.com/in/yourprofile) · [GitHub](https://github.com/yourusername)
