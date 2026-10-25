from soc_analyzer.parsers import parse_lines


def ssh(msg, ts="Mar 20 10:00:00", proc="sshd[1]"):
    return f"{ts} ubuntu {proc}: {msg}"


def test_failed_and_accepted_ssh():
    events = parse_lines([
        ssh("Failed password for root from 10.0.0.1 port 22 ssh2"),
        ssh("Failed password for invalid user oracle from 10.0.0.1 port 22 ssh2"),
        ssh("Accepted publickey for alice from 10.0.0.2 port 22 ssh2"),
    ], year=2026)
    assert [(e.action, e.user, e.detail["method"]) for e in events] == [
        ("failed", "root", "password"),
        ("failed", "oracle", "password"),
        ("accepted", "alice", "publickey"),
    ]
    assert events[1].detail["invalid_user"] is True


def test_iso_timestamps_are_parsed():
    events = parse_lines([ssh("Failed password for root from 10.0.0.1 port 22 ssh2",
                              ts="2026-03-01T10:00:01.123456+00:00")])
    assert len(events) == 1 and events[0].ts.year == 2026


def test_ipv6_address_kept_whole():
    events = parse_lines([ssh("Failed password for root from 2001:db8::66 port 22 ssh2")], year=2026)
    assert events[0].ip == "2001:db8::66"


def test_message_repeated_expands():
    events = parse_lines([
        ssh("Failed password for root from 10.0.0.1 port 22 ssh2"),
        ssh("message repeated 9 times: [ Failed password for root from 10.0.0.1 port 22 ssh2]"),
    ], year=2026)
    assert len(events) == 10


def test_sshd_session_process_name():
    events = parse_lines([ssh("Failed password for root from 10.0.0.1 port 22 ssh2", proc="sshd-session[9]")],
                         year=2026)
    assert len(events) == 1


def test_http_with_spaces_in_path_and_url_decoding():
    events = parse_lines([
        '1.2.3.4 - - [20/Mar/2024:10:10:00 +0000] "GET /index.php?id=1\' OR \'1\'=\'1 HTTP/1.1" 500 256 "-" "sqlmap/1.7"',
        '1.2.3.4 - - [20/Mar/2024:10:10:01 +0000] "GET /a?q=%27%20OR%201%3D1 HTTP/1.1" 200 1 "-" "x"',
    ])
    assert len(events) == 2
    assert events[0].detail["status"] == 500
    assert events[1].detail["path"] == "/a?q=' OR 1=1"


def test_real_bind_format_uses_client_ip_not_server_ip():
    line = ("Mar 20 10:00:00 ubuntu named[1]: client @0x7f1 192.168.1.50#53211 (evil.ru): "
            "query: evil.ru IN A +E(0)K (10.0.0.1)")
    events = parse_lines([line], year=2026)
    assert events[0].ip == "192.168.1.50"
    assert events[0].detail["domain"] == "evil.ru"


def test_year_inferred_from_lines_that_have_one():
    events = parse_lines([
        '1.2.3.4 - - [20/Mar/2024:10:00:00 +0000] "GET / HTTP/1.1" 200 1 "-" "x"',
        ssh("Failed password for root from 10.0.0.1 port 22 ssh2", ts="Mar 20 10:00:05"),
    ])
    assert {e.ts.year for e in events} == {2024}


def test_garbage_lines_are_ignored():
    assert parse_lines(["", "hello world", "Mar 99 99:99:99 host sshd[1]: nope"]) == []
