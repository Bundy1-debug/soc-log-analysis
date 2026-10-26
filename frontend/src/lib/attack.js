// The ATT&CK techniques this tool can detect, grouped by tactic (kill-chain order).
// Mirrors soc_analyzer/mitre.py.
export const ATTACK_MATRIX = [
  { tactic: "Reconnaissance", id: "TA0043", techniques: [
    { id: "T1595.002", name: "Vulnerability Scanning" },
    { id: "T1595.003", name: "Wordlist Scanning" },
  ]},
  { tactic: "Initial Access", id: "TA0001", techniques: [
    { id: "T1190", name: "Exploit Public-Facing App" },
    { id: "T1078", name: "Valid Accounts" },
  ]},
  { tactic: "Execution", id: "TA0002", techniques: [
    { id: "T1059.004", name: "Unix Shell" },
  ]},
  { tactic: "Persistence", id: "TA0003", techniques: [
    { id: "T1136.001", name: "Local Account" },
    { id: "T1098", name: "Account Manipulation" },
    { id: "T1098.004", name: "SSH Authorized Keys" },
    { id: "T1505.003", name: "Web Shell" },
    { id: "T1053.003", name: "Cron" },
    { id: "T1543.002", name: "Systemd Service" },
  ]},
  { tactic: "Privilege Escalation", id: "TA0004", techniques: [
    { id: "T1548.003", name: "Sudo / Sudo Caching" },
  ]},
  { tactic: "Credential Access", id: "TA0006", techniques: [
    { id: "T1110.001", name: "Password Guessing" },
    { id: "T1110.003", name: "Password Spraying" },
    { id: "T1003.008", name: "/etc/passwd & /etc/shadow" },
    { id: "T1552.004", name: "Private Keys" },
  ]},
  { tactic: "Defense Evasion", id: "TA0005", techniques: [
    { id: "T1070.002", name: "Clear System Logs" },
    { id: "T1070.003", name: "Clear Command History" },
  ]},
  { tactic: "Command and Control", id: "TA0011", techniques: [
    { id: "T1071.004", name: "DNS" },
    { id: "T1568.002", name: "Domain Generation Algo" },
  ]},
  { tactic: "Exfiltration", id: "TA0010", techniques: [
    { id: "T1048.003", name: "Alt Protocol (DNS)" },
    { id: "T1041", name: "Over C2 Channel" },
  ]},
];
