import io

import pytest

flask = pytest.importorskip("flask")

import webapp.app as webapp  # noqa: E402


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(webapp, "GEO_ENABLED", False)      # never call the internet from tests
    return webapp.app.test_client()


def test_index_has_security_headers(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert "script-src 'self'" in resp.headers["Content-Security-Policy"]
    assert resp.headers["X-Content-Type-Options"] == "nosniff"


def test_frontend_renders_log_data_safely():
    """
    The React frontend renders attacker-controlled log fields through JSX text nodes.
    The only raw-HTML sink is the JSON highlighter in RawJson.jsx, and it must escape
    &, < and > before inserting. Fail if raw HTML is injected anywhere else.
    """
    src = webapp.ROOT / "frontend" / "src"
    offenders = []
    for path in src.rglob("*.jsx"):
        text = path.read_text()
        if "dangerouslySetInnerHTML" in text and path.name != "RawJson.jsx":
            offenders.append(path.name)
    assert offenders == [], f"unescaped HTML sink(s): {offenders}"

    raw = (src / "components" / "RawJson.jsx").read_text()
    assert 'replace(/&/g, "&amp;")' in raw and 'replace(/</g, "&lt;")' in raw


def test_sample_route(client):
    data = client.post("/analyze-sample").get_json()
    assert data["summary"]["breaches"] == 4   # SSH login + web login + webshell + reverse shell


def test_upload_returns_payload_as_plain_data(client):
    log = "".join(f'6.6.6.6 - - [20/Mar/2024:10:00:0{i} +0000] "GET /.env HTTP/1.1" 200 1 "-" '
                  f'"sqlmap<img src=x onerror=alert(1)>"\n' for i in range(3))
    resp = client.post("/analyze", data={"logfile": (io.BytesIO(log.encode()), "x.log")},
                       content_type="multipart/form-data")
    assert resp.status_code == 200
    assert resp.get_json()["alerts"][0]["details"]["agents"] == ["sqlmap<img src=x onerror=alert(1)>"]


def test_upload_without_file(client):
    assert client.post("/analyze").status_code == 400


def test_geoip_rejects_non_ip(client):
    assert client.get("/geoip/not-an-ip").status_code == 400


def test_debug_is_off_by_default():
    assert webapp.app.debug is False
