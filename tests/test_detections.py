from soc_analyzer.detections import (detect_dns, detect_http, detect_ssh_breach,
                                     detect_ssh_brute_force, peak_in_window)
from soc_analyzer.intel import ThreatIntel
from soc_analyzer.parsers import parse_lines


def fails(ip, n, start_sec=0, step=2, user="root"):
    return [f"Mar 20 10:{(start_sec + i * step) // 60:02d}:{(start_sec + i * step) % 60:02d} ubuntu sshd[1]: "
            f"Failed password for {user} from {ip} port 22 ssh2" for i in range(n)]


def accepted(ip, ts, user="root", method="password"):
    return f"Mar 20 {ts} ubuntu sshd[1]: Accepted {method} for {user} from {ip} port 22 ssh2"


def parse(lines):
    return parse_lines(lines, year=2026)


# ── Sliding window ───────────────────────────────────────────────

def test_peak_in_window():
    events = parse(fails("1.1.1.1", 6, step=20))           # one every 20s
    assert peak_in_window([e.ts for e in events], 60) == 4  # 0,20,40,60


def test_slow_failures_are_not_brute_force():
    lines = [f"Mar {d} 10:00:00 ubuntu sshd[1]: Failed password for root from 10.9.9.9 port 1 ssh2"
             for d in range(1, 6)]
    assert detect_ssh_brute_force(parse(lines)) == []


def test_fast_failures_are_brute_force_with_all_users():
    lines = fails("1.1.1.1", 4) + fails("1.1.1.1", 2, start_sec=8, user="admin")
    [alert] = detect_ssh_brute_force(parse(lines))
    assert alert["mitre"]["technique_id"] == "T1110.001"
    assert {u["user"]: u["attempts"] for u in alert["details"]["users_targeted"]} == {"root": 4, "admin": 2}


def test_password_spraying():
    lines = [f"Mar 20 10:00:0{i} ubuntu sshd[1]: Failed password for invalid user u{i} from 5.5.5.5 port 1 ssh2"
             for i in range(6)]
    [alert] = detect_ssh_brute_force(parse(lines))
    assert alert["mitre"]["technique_id"] == "T1110.003"


# ── Breach ───────────────────────────────────────────────────────

def test_success_after_brute_force_is_critical_breach():
    lines = fails("1.1.1.1", 6) + [accepted("1.1.1.1", "10:00:30", method="keyboard-interactive/pam")]
    [alert] = detect_ssh_breach(parse(lines))
    assert alert["severity"] == "CRITICAL"
    assert alert["details"]["compromised_users"] == ["root"]
    assert alert["mitre"]["technique_id"] == "T1078"


def test_success_before_failures_is_not_a_breach():
    lines = [accepted("1.1.1.1", "09:00:00")] + fails("1.1.1.1", 6)
    assert detect_ssh_breach(parse(lines)) == []


# ── HTTP ─────────────────────────────────────────────────────────

def http(ip, path, status=404, agent="Mozilla/5.0", sec=0):
    return f'{ip} - - [20/Mar/2024:10:00:{sec:02d} +0000] "GET {path} HTTP/1.1" {status} 1 "-" "{agent}"'


def test_payloads_raise_t1190():
    lines = [http("6.6.6.6", "/index.php?id=1' OR '1'='1", sec=0),
             http("6.6.6.6", "/search?q=<script>alert(1)</script>", sec=1),
             http("6.6.6.6", "/../../../etc/passwd", sec=2)]
    [alert] = detect_http(parse_lines(lines))
    assert alert["mitre"]["technique_id"] == "T1190"
    assert set(alert["details"]["payloads"]) == {"sql_injection", "xss", "path_traversal", "file_inclusion"}


def test_curl_alone_is_not_suspicious():
    lines = [http("7.7.7.7", "/health", status=200, agent="curl/8.0", sec=i) for i in range(10)]
    assert detect_http(parse_lines(lines)) == []


def test_exposed_secret_raises_severity():
    base = [http("8.8.4.4", p, sec=i) for i, p in enumerate(["/admin", "/phpmyadmin"])]
    leak = base + [http("8.8.4.4", "/.env", status=200, sec=3)]
    no_leak = base + [http("8.8.4.4", "/.env", status=404, sec=3)]
    [a_leak] = detect_http(parse_lines(leak))
    [a_safe] = detect_http(parse_lines(no_leak))
    assert a_leak["details"]["exposed_paths"] == ["/.env"]
    assert a_leak["severity"] != a_safe["severity"]


# ── DNS ──────────────────────────────────────────────────────────

def dns(domain, client="10.1.1.1"):
    return f"Mar 20 10:00:00 ubuntu named[1]: query: {domain} IN A + ({client})"


def test_no_false_positive_on_ec2_or_tld_alone():
    lines = [dns("ec2.amazonaws.com"), dns("abc2.com"), dns("www.baidu.cn")]
    assert detect_dns(parse(lines)) == []


def test_malware_keyword_and_intel():
    intel = ThreatIntel(bad_domains={"evil-dropper.ru"})
    lines = [dns("malware-c2.ru"), dns("cdn.evil-dropper.ru")]
    [alert] = detect_dns(parse(lines), intel)
    assert alert["details"]["indicators"]["threat_intel"] == 1
    assert alert["severity"] == "HIGH"
    assert alert["ip_role"] == "internal host"


def test_dga_domain():
    [alert] = detect_dns(parse([dns("xk7q2mzp9wtr4vbn.top")]))
    assert alert["mitre"]["technique_id"] == "T1568.002"
