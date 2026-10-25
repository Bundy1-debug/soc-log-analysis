"""
Parsers — turn raw log lines into normalized Event objects.

Supported formats:
  - sshd via syslog (auth.log): classic "Mar 20 10:01:22" or RFC 3339 "2026-03-20T10:01:22+00:00"
  - Apache / Nginx combined access log
  - BIND (named) query log
"""

import ipaddress
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from urllib.parse import unquote_plus


@dataclass
class Event:
    ts:      datetime
    source:  str              # ssh | http | dns
    action:  str              # failed | accepted | request | query
    ip:      str
    user:    str = ""
    detail:  dict = field(default_factory=dict)
    line_no: int = 0


# ── Regex patterns ───────────────────────────────────────────────
SYSLOG = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2}"                      # Mar 20 10:01:22
    r"|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"  # 2026-03-20T10:01:22.123+00:00
    r"\s+\S+\s+(?P<proc>[\w./-]+)(?:\[\d+\])?:\s+(?P<msg>.*)$"
)
# rsyslog collapses identical lines: "message repeated 9 times: [ Failed password for ... ]"
REPEATED = re.compile(r"^message repeated (?P<n>\d+) times: \[\s*(?P<msg>.*?)\s*\]$")

SSH_FAILED = re.compile(
    r"^Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>.*?) from (?P<ip>\S+) port \d+"
)
SSH_ACCEPTED = re.compile(
    r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port \d+"
)

DNS_QUERY       = re.compile(r"query: (?P<domain>\S+) IN (?P<qtype>\S+)")
DNS_CLIENT      = re.compile(r"client (?:@\S+ )?(?P<ip>[0-9a-fA-F:.]+)#\d+")  # real BIND: "client @0x.. 1.2.3.4#53211"
DNS_TRAILING_IP = re.compile(r"\((?P<ip>[0-9a-fA-F:.]+)\)\s*$")                # simplified lab format

HTTP = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>.*?) HTTP/[\d.]+" '     # lazy path: tolerates spaces in raw payloads
    r'(?P<status>\d{3}) (?P<bytes>\S+)'
    r'(?: "[^"]*" "(?P<agent>[^"]*)")?'
)


# ── Helpers ──────────────────────────────────────────────────────

def valid_ip(text):
    """Return the normalized IP string, or None if `text` is not an IPv4/IPv6 address."""
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def _syslog_time(raw):
    """Return (datetime, year_known). Classic syslog has no year; it is filled in later."""
    if raw[0].isdigit():
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).replace(tzinfo=None), True
    # 2000 is a leap year, so "Feb 29" parses; the real year is set by _resolve_years()
    return datetime.strptime(f"2000 {' '.join(raw.split())}", "%Y %b %d %H:%M:%S"), False


def _parse_http(line, line_no):
    m = HTTP.match(line)
    if not m:
        return None
    ip = valid_ip(m["ip"])
    if not ip:
        return None
    try:
        # Timezone dropped on purpose: classic syslog has none, so we compare wall-clock times
        ts = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z").replace(tzinfo=None)
    except ValueError:
        return None
    return Event(ts, "http", "request", ip, detail={
        "method": m["method"],
        "path":   unquote_plus(m["path"]),     # decode %27 → ' so payload rules see the real text
        "status": int(m["status"]),
        "bytes":  int(m["bytes"]) if m["bytes"].isdigit() else 0,   # "-" = no body
        "agent":  m["agent"] or "",
    }, line_no=line_no)


def _parse_syslog(line, line_no):
    """Return (events, year_known). Several events when rsyslog collapsed repeats."""
    m = SYSLOG.match(line)
    if not m:
        return [], True
    try:
        ts, year_known = _syslog_time(m["ts"])
    except ValueError:
        return [], True
    proc, msg, count = m["proc"], m["msg"], 1

    rep = REPEATED.match(msg)
    if rep:
        count, msg = int(rep["n"]), rep["msg"]

    event = None
    if proc.startswith("sshd"):                    # sshd, and sshd-session on OpenSSH 9.8+
        f = SSH_FAILED.match(msg)
        a = SSH_ACCEPTED.match(msg) if not f else None
        hit = f or a
        ip = valid_ip(hit["ip"]) if hit else None
        if ip:
            event = Event(ts, "ssh", "failed" if f else "accepted", ip, hit["user"],
                          {"method": hit["method"], "invalid_user": bool(f and f["invalid"])},
                          line_no)
    elif proc == "named":
        q = DNS_QUERY.search(msg)
        c = DNS_CLIENT.search(msg) or DNS_TRAILING_IP.search(msg)
        ip = valid_ip(c["ip"]) if c else None
        if q and ip:
            event = Event(ts, "dns", "query", ip,
                          detail={"domain": q["domain"].rstrip(".").lower(), "qtype": q["qtype"]},
                          line_no=line_no)

    if not event:
        return [], True
    return [event] + [Event(event.ts, event.source, event.action, event.ip, event.user,
                            dict(event.detail), line_no) for _ in range(count - 1)], year_known


def _resolve_years(events, year):
    """
    Give year-less syslog events a real year:
      1. the year passed by the caller, else
      2. the most common year among lines that do carry one (e.g. the HTTP log), else
      3. the current year — or last year if that would put the event in the future (Dec logs read in Jan).
    """
    if not events:
        return
    if year is None:
        known = Counter(e.ts.year for e, k in events if k)
        if known:
            year = known.most_common(1)[0][0]
    now = datetime.now()
    for e, known_year in events:
        if known_year:
            continue
        y = year if year is not None else now.year
        try:
            e.ts = e.ts.replace(year=y)
            if year is None and e.ts > now + timedelta(days=1):
                e.ts = e.ts.replace(year=y - 1)
        except ValueError:                          # Feb 29 in a non-leap year
            e.ts = e.ts.replace(year=y, day=28)


# ── Public API ───────────────────────────────────────────────────

def parse_lines(lines, year=None):
    """Parse an iterable of log lines (any mix of formats) into Events sorted by time."""
    tagged = []
    for no, line in enumerate(lines, 1):
        line = line.rstrip("\r\n")
        if not line:
            continue
        http = _parse_http(line, no)
        if http:
            tagged.append((http, True))
            continue
        events, year_known = _parse_syslog(line, no)
        tagged.extend((e, year_known) for e in events)

    _resolve_years(tagged, year)
    return sorted((e for e, _ in tagged), key=lambda e: e.ts)
