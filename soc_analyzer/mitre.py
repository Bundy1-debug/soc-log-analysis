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
    "T1548.003": ("Abuse Elevation Control Mechanism: Sudo and Sudo Caching", "TA0004", "Privilege Escalation"),
    "T1136.001": ("Create Account: Local Account",                     "TA0003", "Persistence"),
    "T1098":     ("Account Manipulation",                              "TA0003", "Persistence"),
    "T1595.003": ("Active Scanning: Wordlist Scanning",                "TA0043", "Reconnaissance"),
    "T1505.003": ("Server Software Component: Web Shell",              "TA0003", "Persistence"),
    "T1041":     ("Exfiltration Over C2 Channel",                      "TA0010", "Exfiltration"),
    "T1048.003": ("Exfiltration Over Alternative Protocol: Unencrypted Non-C2 Protocol", "TA0010", "Exfiltration"),
}


def technique(technique_id):
    name, tactic_id, tactic = TECHNIQUES[technique_id]
    return {
        "technique_id": technique_id,
        "technique":    name,
        "tactic_id":    tactic_id,
        "tactic":       tactic,
        "url":          f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
    }
