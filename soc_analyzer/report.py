"""
Text report for the terminal.
"""

COLORS = {
    "CRITICAL": "\033[91m", "HIGH": "\033[31m", "MEDIUM": "\033[33m", "LOW": "\033[34m",
    "BOLD": "\033[1m", "DIM": "\033[2m", "GREEN": "\033[92m", "CYAN": "\033[96m", "RESET": "\033[0m",
}
WIDTH = 72


def format_text(report, color=True):
    def c(key, text):
        return f"{COLORS[key]}{text}{COLORS['RESET']}" if color else str(text)

    s = report["summary"]
    out = [
        "",
        c("BOLD", "=" * WIDTH),
        c("BOLD", "  SOC LOG ANALYZER — THREAT DETECTION REPORT"),
        c("BOLD", "=" * WIDTH),
        f"  Generated  : {report['generated_at']}",
        f"  Inputs     : {', '.join(report['inputs']) or '—'}",
        f"  Parsed     : {s['events_parsed']} events from {s['lines_read']} lines "
        f"({', '.join(f'{k}: {v}' for k, v in s['events_by_source'].items()) or 'none'})",
        c("BOLD", "-" * WIDTH),
        f"  Incidents  : {s['incidents']}    Alerts : {s['alerts']}    "
        f"Breaches : {c('CRITICAL', s['breaches']) if s['breaches'] else 0}",
        "  Severity   : " + "  ".join(f"{c(k, k)} {v}" for k, v in s["by_severity"].items()),
    ]

    if not report["incidents"]:
        out += ["", c("GREEN", "  No threats detected above threshold."), ""]
        return "\n".join(out)

    for inc in report["incidents"]:
        sev = inc["severity"]
        out += [
            "",
            c("BOLD", f"  [{inc['id']}] {inc['ip']}  ") + c(sev, f"[{sev}]")
            + (c("CRITICAL", "  ⚠ BREACH") if inc["breach"] else ""),
            f"    Window     : {inc['first_seen']} → {inc['last_seen']}",
            f"    Kill chain : {inc['kill_chain']}",
            f"    ATT&CK     : {', '.join(inc['techniques'])}",
        ]
        for a in (a for a in report["alerts"] if a["id"] in inc["alert_ids"]):
            badge = c(a["severity"], a["severity"].ljust(8))
            out.append(f"    • {badge} {a['title']}: {a['summary']}")
            d = a["details"]
            if d.get("users_targeted"):
                users = ", ".join(f"{u['user']}({u['attempts']})" for u in d["users_targeted"][:6])
                out.append(c("DIM", f"        accounts: {users}"))
            if d.get("top_paths"):
                out.append(c("DIM", f"        paths   : {', '.join(d['top_paths'][:4])}"))
            if d.get("domains"):
                out.append(c("DIM", f"        domains : {', '.join(d['domains'])}"))
            if a.get("geo", {}).get("country"):
                out.append(c("DIM", f"        geo     : {a['geo']['country']} — {a['geo']['isp']}"))
        out.append(c("CYAN", "    Response:"))
        out += [f"      {n}. {step}" for n, step in enumerate(inc["response"], 1)]

    out += ["", c("BOLD", "=" * WIDTH), ""]
    return "\n".join(out)
