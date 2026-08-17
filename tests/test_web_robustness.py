import pytest

from src.atlasscan import web


def test_normalize_url_http_default():
    assert web._normalize_url("example.com", 80) == \
        "http://example.com:80"


def test_normalize_url_https_for_443():
    assert web._normalize_url("example.com", 443) == \
        "https://example.com:443"


def test_normalize_url_preserves_existing_scheme():
    assert web._normalize_url("https://example.com/path", 443) == \
        "https://example.com/path"


def test_normalize_url_strips_whitespace():
    assert web._normalize_url("  example.com  ", 80) == \
        "http://example.com:80"


def test_decode_body_empty():
    assert web._decode_body(b"") == ""


def test_decode_body_invalid_utf8():
    result = web._decode_body(b"\xff\xfehello")
    assert "hello" in result


def test_extract_title_returns_title():
    body = "<html><head><title>AtlasScan</title></head></html>"

    assert web._extract_title(body) == "AtlasScan"


def test_extract_title_handles_whitespace():
    body = "<title>  Atlas   Scan  </title>"

    assert web._extract_title(body) == "Atlas Scan"


def test_extract_title_missing_returns_none():
    assert web._extract_title("<html><body>Hello</body></html>") is None


def test_extract_title_missing_closing_tag_returns_none():
    assert web._extract_title("<title>AtlasScan") is None


def test_security_headers_extracts_known_headers():
    headers = {
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY",
        "server": "Apache",
    }

    result = web._security_headers(headers)

    assert result["Content-Security-Policy"] == "default-src 'self'"
    assert result["X-Frame-Options"] == "DENY"
    assert result["Strict-Transport-Security"] is None


def test_security_headers_missing_values_are_none():
    result = web._security_headers({})

    assert result["Content-Security-Policy"] is None
    assert result["Strict-Transport-Security"] is None
    assert result["X-Frame-Options"] is None
    assert result["X-Content-Type-Options"] is None


def test_request_handles_url_error(monkeypatch):
    def fake_urlopen(*args, **kwargs):
        raise web.URLError("connection failed")

    monkeypatch.setattr(web, "urlopen", fake_urlopen)

    result = web._request("http://example.com")

    assert result["status_code"] is None
    assert result["body"] == b""
    assert result["headers"] == {}
    assert result["error"] is not None
    assert "connection failed" in result["error"]


def test_request_handles_timeout(monkeypatch):
    def fake_urlopen(*args, **kwargs):
        raise TimeoutError("timed out")

    monkeypatch.setattr(web, "urlopen", fake_urlopen)

    result = web._request("http://example.com")

    assert result["status_code"] is None
    assert result["error"] == "timed out"


def test_request_handles_unexpected_error(monkeypatch):
    def fake_urlopen(*args, **kwargs):
        raise RuntimeError("unexpected failure")

    monkeypatch.setattr(web, "urlopen", fake_urlopen)

    result = web._request("http://example.com")

    assert result["status_code"] is None
    assert result["error"] == "unexpected failure"


def test_inspect_web_handles_request_failure(monkeypatch):
    def fake_request(*args, **kwargs):
        return {
            "status_code": None,
            "url": "http://example.com:80",
            "headers": {},
            "body": b"",
            "error": "connection failed",
        }

    monkeypatch.setattr(web, "_request", fake_request)

    result = web.inspect_web("example.com", 80)

    assert result["status_code"] is None
    assert result["title"] is None
    assert result["server"] is None
    assert result["content_length"] is None
    assert result["error"] == "connection failed"


def test_check_robots_handles_failure(monkeypatch):
    def fake_request(*args, **kwargs):
        return {
            "status_code": None,
            "url": "http://example.com:80/robots.txt",
            "headers": {},
            "body": b"",
            "error": "connection failed",
        }

    monkeypatch.setattr(web, "_request", fake_request)

    result = web.check_robots("example.com", 80)

    assert result["exists"] is False
    assert result["content"] is None
    assert result["error"] == "connection failed"


def test_discover_common_paths_skips_failed_requests(monkeypatch):
    def fake_request(*args, **kwargs):
        return {
            "status_code": None,
            "url": args[0] if args else "",
            "headers": {},
            "body": b"",
            "error": "connection failed",
        }

    monkeypatch.setattr(web, "_request", fake_request)

    result = web.discover_common_paths("example.com", 80)

    assert result == []


def test_discover_common_paths_returns_successful_paths(monkeypatch):
    def fake_request(*args, **kwargs):
        return {
            "status_code": 200,
            "url": args[0] if args else "",
            "headers": {
                "content-type": "text/html",
                "content-length": "42",
            },
            "body": b"<html></html>",
            "error": None,
        }

    monkeypatch.setattr(web, "_request", fake_request)

    result = web.discover_common_paths("example.com", 80)

    assert len(result) == 5
    assert all(item["status_code"] == 200 for item in result)
