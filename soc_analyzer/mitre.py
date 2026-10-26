"""
MITRE ATT&CK mapping — the common language SOC teams use to describe attacker behavior.
https://attack.mitre.org
"""

# technique id → (technique name, tactic id, tactic name)
TECHNIQUES = {
    "T1595.002": ("Active Scanning: Vulnerability Scanning",           "TA0043", "Reconnaissance"),
    "T1190":     ("Exploit Public-Facing Application",                 "TA0001", "Initial Access"),
    "T1078":     ("Valid Accounts",                                    "TA0001", "Initial Access"),
    "T1110.001": ("Brute Force: Password Guessing",                    "TA0006", "Credential Access"),
    "T1110.003": ("Brute Force: Password Spraying",                    "TA0006", "Credential Access"),
    "T1071.004": ("Application Layer Protocol: DNS",                   "TA0011", "Command and Control"),
    "T1568.002": ("Dynamic Resolution: Domain Generation Algorithms",  "TA0011", "Command and Control"),
    "T1059.004": ("Command and Scripting Interpreter: Unix Shell",     "TA0002", "Execution"),
    "T1105":     ("Ingress Tool Transfer",                             "TA0011", "Command and Control"),
    "T1003.008": ("OS Credential Dumping: /etc/passwd and /etc/shadow", "TA0006", "Credential Access"),
    "T1552.004": ("Unsecured Credentials: Private Keys",               "TA0006", "Credential Access"),
    "T1053.003": ("Scheduled Task/Job: Cron",                          "TA0003", "Persistence"),
    "T1098.004": ("Account Manipulation: SSH Authorized Keys",         "TA0003", "Persistence"),
    "T1543.002": ("Create or Modify System Process: Systemd Service",  "TA0003", "Persistence"),
    "T1070.002": ("Indicator Removal: Clear Linux or Mac System Logs", "TA0005", "Defense Evasion"),
    "T1070.003": ("Indicator Removal: Clear Command History",          "TA0005", "Defense Evasion"),
    "T1548.003": ("Abuse Elevation Control Mechanism: Sudo and Sudo Caching", "TA0004", "Privilege Escalation"),
    "T1136.001": ("Create Account: Local Account",                     "TA0003", "Persistence"),
    "T1098":     ("Account Manipulation",                              "TA0003", "Persistence"),
    "T1595.003": ("Active Scanning: Wordlist Scanning",                "TA0043", "Reconnaissance"),
    "T1505.003": ("Server Software Component: Web Shell",              "TA0003", "Persistence"),
    "T1041":     ("Exfiltration Over C2 Channel",                      "TA0010", "Exfiltration"),
    "T1048.003": ("Exfiltration Over Alternative Protocol: Unencrypted Non-C2 Protocol", "TA0010", "Exfiltration"),
}


def technique(technique_id):
    if technique_id is None:                 # behavioral anomaly: no single ATT&CK technique
        return {"technique_id": "N/A", "technique": "Behavioral anomaly",
                "tactic_id": "-", "tactic": "Anomaly", "url": ""}
    name, tactic_id, tactic = TECHNIQUES[technique_id]
    return {
        "technique_id": technique_id,
        "technique":    name,
        "tactic_id":    tactic_id,
        "tactic":       tactic,
        "url":          f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
    }
