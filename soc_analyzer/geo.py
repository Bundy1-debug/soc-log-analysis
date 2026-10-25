"""
IP geolocation via ip-api.com (free tier: HTTP only, 15 batch requests/min, 100 IPs per batch).

Privacy: this sends IPs to a third party. In a real SOC, check that sharing them is allowed
before enabling it — set SOC_DISABLE_GEO=1 to switch it off.
"""

import ipaddress
import os

import requests

API = "http://ip-api.com/batch"
FIELDS = "status,query,country,countryCode,regionName,city,isp,org,as"
_cache = {}

PRIVATE = {"country": "Private / Reserved", "countryCode": "LAN", "region": "—", "city": "—",
           "isp": "Internal", "org": "—", "as": "—", "private": True}


def geolocate(ips):
    """Return {ip: geo dict}. Private IPs are labelled locally; unknown/failed lookups are omitted."""
    result, todo = {}, []
    for ip in set(ips):
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if not addr.is_global:
            result[ip] = PRIVATE
        elif ip in _cache:
            result[ip] = _cache[ip]
        else:
            todo.append(ip)

    if todo and os.environ.get("SOC_DISABLE_GEO") != "1":
        for i in range(0, len(todo), 100):
            try:
                resp = requests.post(API, params={"fields": FIELDS},
                                     json=todo[i:i + 100], timeout=5)
                resp.raise_for_status()
                rows = resp.json()
            except (requests.RequestException, ValueError):
                break                              # enrichment is optional: never fail the analysis
            for d in rows:
                if d.get("status") != "success":
                    continue
                _cache[d["query"]] = result[d["query"]] = {
                    "country": d.get("country", ""), "countryCode": d.get("countryCode", ""),
                    "region": d.get("regionName", ""), "city": d.get("city", ""),
                    "isp": d.get("isp", ""), "org": d.get("org", ""), "as": d.get("as", ""),
                    "private": False,
                }
    return result
