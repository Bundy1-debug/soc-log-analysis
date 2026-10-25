"""
Threat intelligence — local IOC (Indicator of Compromise) lists.

Files in intel/ hold one indicator per line; '#' starts a comment.
In production these would be fed from a TI platform (MISP, abuse.ch, AbuseIPDB exports).
"""

from dataclasses import dataclass, field
from pathlib import Path

from .parsers import valid_ip


@dataclass
class ThreatIntel:
    bad_ips:     set = field(default_factory=set)
    bad_domains: set = field(default_factory=set)

    def ip_match(self, ip):
        return ip in self.bad_ips

    def domain_match(self, domain):
        """True if the domain or any parent domain is listed (a.b.evil.ru matches evil.ru)."""
        parts = domain.lower().rstrip(".").split(".")
        return any(".".join(parts[i:]) in self.bad_domains for i in range(len(parts) - 1))


def _read_list(path):
    if not path.exists():
        return set()
    items = set()
    for line in path.read_text(errors="replace").splitlines():
        value = line.split("#", 1)[0].strip().lower()
        if value:
            items.add(value)
    return items


def load_intel(directory):
    directory = Path(directory)
    ips = {ip for ip in (valid_ip(v) for v in _read_list(directory / "bad_ips.txt")) if ip}
    return ThreatIntel(ips, _read_list(directory / "bad_domains.txt"))
