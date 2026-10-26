export const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

export const SEV_COLOR = {
  CRITICAL: "var(--crit)",
  HIGH: "var(--high)",
  MEDIUM: "var(--med)",
  LOW: "var(--low)",
};

// Which alert tab a type belongs to
const SOURCE_OF = {
  SSH_BRUTE_FORCE: "ssh", SSH_LOGIN_AFTER_BRUTE_FORCE: "ssh",
  HTTP_SCAN: "http", WEB_LOGIN_BRUTE_FORCE: "http", WEB_DIRECTORY_BRUTE_FORCE: "http",
  WEBSHELL: "http", WEB_LARGE_TRANSFER: "http",
  SUSPICIOUS_DNS: "dns", DNS_TUNNELING: "dns", DNS_BEACONING: "dns",
  SUDO_ABUSE: "host", SU_BRUTE_FORCE: "host", USER_CREATED: "host", PRIV_GROUP_ADD: "host",
};

export function sourceOf(type) {
  if (SOURCE_OF[type]) return SOURCE_OF[type];
  if (type.startsWith("EDR_")) return "host";
  if (type.startsWith("ANOMALY_")) return "anom";
  return "host";
}

// "2024-03-20 10:01:22" -> "03-20 10:01:22"
export const shortTime = (ts) => (ts || "").slice(5);
export const clockTime = (ts) => (ts || "").slice(11);

export const fmtBytes = (n) => {
  if (!n) return "0 B";
  const u = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(n) / Math.log(1024));
  return `${(n / Math.pow(1024, i)).toFixed(i ? 1 : 0)} ${u[i]}`;
};

// Mirrors soc_analyzer/correlation.is_breach: alerts proving the attacker got in.
export function isBreachAlert(a) {
  const d = a.details || {};
  return (
    a.type === "SSH_LOGIN_AFTER_BRUTE_FORCE" ||
    (a.type === "WEB_LOGIN_BRUTE_FORCE" && d.successful_logins > 0) ||
    (a.type === "WEBSHELL" && d.command_requests > 0) ||
    ["EDR_REVERSE_SHELL", "EDR_CLEAR_LOGS", "EDR_CREDENTIAL_ACCESS_FILES"].includes(a.type)
  );
}

export const flagEmoji = (cc) => {
  if (!cc || cc.length !== 2 || cc === "LAN") return "🏴";
  return String.fromCodePoint(...[...cc.toUpperCase()].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65));
};
