"""
Web behavior detections — patterns across many requests from one IP:
login brute force, directory brute force, webshell use, large data transfers.
"""

import re
from collections import defaultdict

from . import config as cfg
from .detections import EXPOSURE_PATHS, classify_severity, make_alert, peak_in_window

LOGIN_PATHS = re.compile(
    r"^/(wp-login\.php|xmlrpc\.php|login|signin|sign-in|user/login|admin/login|auth|session|"
    r"api/(auth|login|token|session))\b", re.IGNORECASE)
LOGIN_SUCCESS = {302, 303}                         # most login forms redirect on success (WordPress: 302)

SCRIPT_EXT = re.compile(r"\.(php\d?|phtml|jsp|jspx|aspx?|cgi|pl)(\?|$)", re.IGNORECASE)
UPLOAD_DIRS = re.compile(r"/(uploads?|images?|img|media|files|tmp|temp|cache|static)/", re.IGNORECASE)
COMMAND_PARAM = re.compile(r"[?&](cmd|exec|command|execute|shell|run|c)=", re.IGNORECASE)

BIG_FILES = re.compile(r"\.(iso|img|mp4|mkv|mov|dmg|exe|msi|deb|rpm|apk)(\?|$)", re.IGNORECASE)   # expected large downloads
DATA_FILES = re.compile(r"\.(sql|db|sqlite|bak|dump|zip|tar|gz|tgz|7z|rar|csv|xlsx?)(\?|$)", re.IGNORECASE)


def http_requests(events):
    groups = defaultdict(list)
    for e in events:
        if e.source == "http" and e.action == "request":
            groups[e.ip].append(e)
    return groups


# ── Login brute force ────────────────────────────────────────────

def detect_web_login_brute_force(events):
    alerts = []
    for ip, reqs in http_requests(events).items():
        posts = [e for e in reqs if e.detail["method"] == "POST" and LOGIN_PATHS.search(e.detail["path"])]
        failures = [e for e in posts if e.detail["status"] not in LOGIN_SUCCESS]
        peak = peak_in_window([e.ts for e in failures], cfg.WEB_LOGIN_WINDOW_SECONDS)
        if peak < cfg.WEB_LOGIN_THRESHOLD:
            continue
        # A redirect after the burst = the form accepted a password
        success = [e for e in posts if e.detail["status"] in LOGIN_SUCCESS and e.ts >= failures[0].ts]
        severity = "CRITICAL" if success else classify_severity(len(failures), cfg.SSH_SEVERITY)
        alerts.append(make_alert(
            "WEB_LOGIN_BRUTE_FORCE",
            "Web login brute force" + (" — then a successful login" if success else ""),
            ip, "attacker",
            severity,
            "T1078" if success else "T1110.001",
            failures + success,
            f"{len(failures)} failed login POSTs (peak {peak} in {cfg.WEB_LOGIN_WINDOW_SECONDS}s)"
            + (f", followed by {len(success)} successful login redirect(s) — account likely compromised" if success else ""),
            login_paths=sorted({e.detail["path"].split("?")[0] for e in posts}),
            failed_attempts=len(failures),
            successful_logins=len(success),
            peak_in_window=peak,
        ))
    return alerts


# ── Directory / file brute force ─────────────────────────────────

def detect_directory_brute_force(events):
    alerts = []
    for ip, reqs in http_requests(events).items():
        misses = [e for e in reqs if e.detail["status"] == 404]
        peak = peak_in_window([e.ts for e in misses], cfg.DIRBUST_WINDOW_SECONDS)
        if peak < cfg.DIRBUST_THRESHOLD:
            continue
        found = [e for e in reqs if 200 <= e.detail["status"] < 400 and e.ts >= misses[0].ts]
        alerts.append(make_alert(
            "WEB_DIRECTORY_BRUTE_FORCE",
            "Directory brute force",
            ip, "attacker",
            classify_severity(len(misses), (2000, 500, 100)),
            "T1595.003",
            misses,
            f"{len(misses)} requests for missing pages (peak {peak} in {cfg.DIRBUST_WINDOW_SECONDS}s) "
            f"— a wordlist scan; {len(found)} path(s) answered",
            not_found=len(misses),
            peak_in_window=peak,
            discovered_paths=sorted({e.detail["path"] for e in found})[:10],
            agents=sorted({e.detail["agent"].split("/")[0] for e in misses if e.detail["agent"]}),
        ))
    return alerts


# ── Webshell use ─────────────────────────────────────────────────

def detect_webshell(events):
    alerts = []
    for ip, reqs in http_requests(events).items():
        hits = []
        for e in reqs:
            path, ok = e.detail["path"], 200 <= e.detail["status"] < 300
            if not (ok and SCRIPT_EXT.search(path)):
                continue
            reasons = []
            if COMMAND_PARAM.search(path):
                reasons.append("command_parameter")
            if e.detail["method"] == "POST" and UPLOAD_DIRS.search(path):
                reasons.append("script_in_upload_dir")
            if reasons:
                hits.append((e, reasons))

        commands = [e for e, rs in hits if "command_parameter" in rs]
        uploads = [e for e, rs in hits if "script_in_upload_dir" in rs]
        if not commands and len(uploads) < cfg.WEBSHELL_MIN_POSTS:
            continue
        reqs_hit = [e for e, _ in hits]
        alerts.append(make_alert(
            "WEBSHELL",
            "Possible webshell in use",
            ip, "attacker",
            "CRITICAL" if commands else "HIGH",
            "T1505.003",
            reqs_hit,
            f"{len(reqs_hit)} successful requests to server-side script(s) that look like a webshell"
            + (f"; {len(commands)} carried a command parameter" if commands else ""),
            scripts=sorted({e.detail["path"].split("?")[0] for e in reqs_hit}),
            command_requests=len(commands),
            upload_dir_posts=len(uploads),
        ))
    return alerts


# ── Large data transfer ──────────────────────────────────────────

def detect_large_transfer(events):
    alerts = []
    for ip, reqs in http_requests(events).items():
        served = [e for e in reqs if 200 <= e.detail["status"] < 300 and not BIG_FILES.search(e.detail["path"])]
        total = sum(e.detail["bytes"] for e in served)
        big = [e for e in served if e.detail["bytes"] >= cfg.HTTP_LARGE_RESPONSE_BYTES]
        if not big and total < cfg.HTTP_LARGE_TOTAL_BYTES:
            continue
        evidence = sorted(big or served, key=lambda e: -e.detail["bytes"])[:10]
        evidence.sort(key=lambda e: e.ts)
        sensitive = [e for e in evidence if DATA_FILES.search(e.detail["path"]) or EXPOSURE_PATHS.search(e.detail["path"])]
        alerts.append(make_alert(
            "WEB_LARGE_TRANSFER",
            "Large data transfer to one client",
            ip, "attacker",
            "HIGH" if sensitive else "MEDIUM",
            "T1041",
            evidence,
            f"{total / 1_048_576:.0f} MB served to this IP"
            + (f"; includes data files ({', '.join(sorted({e.detail['path'] for e in sensitive})[:3])})" if sensitive else ""),
            total_bytes=total,
            largest=[{"path": e.detail["path"], "bytes": e.detail["bytes"]} for e in evidence[:5]],
            sensitive_files=sorted({e.detail["path"] for e in sensitive}),
        ))
    return alerts
