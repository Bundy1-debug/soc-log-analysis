"""
Host / privilege detections from auth.log (Pack 3).

These alerts are keyed by the local *user*, not an IP, because the events happen on the
box itself. The alert's `ip` field carries the username so correlation can build a per-user story.
"""

from collections import defaultdict

from . import config as cfg
from .detections import classify_severity, make_alert, peak_in_window


def by_user(events, action):
    groups = defaultdict(list)
    for e in events:
        if e.source == "host" and e.action == action:
            groups[e.user].append(e)
    return groups


# ── Sudo / su abuse ──────────────────────────────────────────────

def detect_sudo_abuse(events):
    alerts = []
    for user, fails in by_user(events, "sudo_fail").items():
        not_sudoer = [e for e in fails if "sudoers" in e.detail["reason"]]
        peak = peak_in_window([e.ts for e in fails], cfg.SUDO_WINDOW_SECONDS)
        # Either a burst of bad passwords, or any "not in sudoers" (someone probing what they can do)
        if peak < cfg.SUDO_FAIL_THRESHOLD and not not_sudoer:
            continue
        severity = "HIGH" if not_sudoer else classify_severity(len(fails), (20, 8, cfg.SUDO_FAIL_THRESHOLD))
        alerts.append(make_alert(
            "SUDO_ABUSE",
            "Sudo privilege probing" if not_sudoer else "Repeated failed sudo",
            user, "local user",
            severity,
            "T1548.003",
            fails,
            f"{len(fails)} failed sudo attempt(s) by '{user}'"
            + (f"; {len(not_sudoer)} where the user is not in sudoers" if not_sudoer else ""),
            reasons=sorted({e.detail["reason"] for e in fails}),
            not_in_sudoers=bool(not_sudoer),
        ))
    return alerts


def detect_su_brute_force(events):
    alerts = []
    for user, fails in by_user(events, "su_fail").items():
        peak = peak_in_window([e.ts for e in fails], cfg.SUDO_WINDOW_SECONDS)
        if peak < cfg.SU_FAIL_THRESHOLD:
            continue
        targets = sorted({e.detail["target"] for e in fails})
        alerts.append(make_alert(
            "SU_BRUTE_FORCE",
            "Repeated failed su",
            user, "local user",
            classify_severity(len(fails), (20, 8, cfg.SU_FAIL_THRESHOLD)),
            "T1548.003",
            fails,
            f"{len(fails)} failed `su` attempt(s) by '{user}' targeting {', '.join(targets)}",
            targets=targets,
        ))
    return alerts


# ── New accounts and privilege grants ────────────────────────────

def detect_account_creation(events):
    alerts = []
    for user, adds in by_user(events, "user_add").items():
        alerts.append(make_alert(
            "USER_CREATED",
            "New local account created",
            user, "new account",
            "MEDIUM",
            "T1136.001",
            adds,
            f"New local account '{user}' created — confirm this was an authorized change",
            tool=adds[0].detail["proc"],
        ))
    return alerts


def detect_privilege_grant(events):
    alerts = []
    for user, grants in by_user(events, "group_add").items():
        groups = sorted({e.detail["group"] for e in grants})
        alerts.append(make_alert(
            "PRIV_GROUP_ADD",
            "Account added to a privileged group",
            user, "local user",
            "HIGH",
            "T1098",
            grants,
            f"'{user}' was added to privileged group(s): {', '.join(groups)} — an attacker's way to keep admin access",
            groups=groups,
        ))
    return alerts


def run_host(events):
    return (detect_sudo_abuse(events) + detect_su_brute_force(events)
            + detect_account_creation(events) + detect_privilege_grant(events))
