from src.atlasscan.webchecks import (
    analyze_web_checks,
)


def test_secure_headers_are_not_flagged():
    headers = {
        "content-security-policy": "default-src 'self'",
        "strict-transport-security": "max-age=31536000; includeSubDomains",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "strict-origin-when-cross-origin",
        "permissions-policy": "geolocation=()",
    }

    result = analyze_web_checks(
        status_code=200,
        headers=headers,
        url="https://example.com/",
    )

    assert result["observation_count"] == 0
    assert result["high_count"] == 0
    assert result["medium_count"] == 0
    assert result["low_count"] == 0


def test_http_url_is_flagged():
    result = analyze_web_checks(
        status_code=200,
        headers={},
        url="http://example.com/",
    )

    assert result["observation_count"] >= 1
    assert any(
        observation["title"] == "HTTP instead of HTTPS"
        for observation in result["observations"]
    )


def test_missing_security_headers_are_detected():
    result = analyze_web_checks(
        status_code=200,
        headers={},
        url="https://example.com/",
    )

    titles = {
        observation["title"]
        for observation in result["observations"]
    }

    assert "Missing Content-Security-Policy" in titles
    assert "Missing Strict-Transport-Security" in titles
    assert "Missing X-Frame-Options" in titles


def test_insecure_cookie_is_detected():
    headers = {
        "content-security-policy": "default-src 'self'",
        "strict-transport-security": "max-age=31536000",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "strict-origin-when-cross-origin",
        "permissions-policy": "geolocation=()",
        "set-cookie": "session=abc123",
    }

    result = analyze_web_checks(
        status_code=200,
        headers=headers,
        url="https://example.com/",
    )

    assert any(
        observation["title"] == "Cookie missing Secure flag"
        for observation in result["observations"]
    )


def test_secure_cookie_is_not_flagged():
    headers = {
        "set-cookie": (
            "session=abc123; "
            "Secure; HttpOnly; SameSite=Lax"
        ),
    }

    result = analyze_web_checks(
        status_code=200,
        headers=headers,
        url="https://example.com/",
    )

    assert not any(
        observation["title"] == "Cookie missing Secure flag"
        for observation in result["observations"]
    )


def test_server_information_disclosure():
    headers = {
        "server": "Apache/2.4.7 (Ubuntu)",
    }

    result = analyze_web_checks(
        status_code=200,
        headers=headers,
        url="https://example.com/",
    )

    assert any(
        observation["title"] == "Server version disclosure"
        for observation in result["observations"]
    )


def test_powered_by_disclosure():
    headers = {
        "x-powered-by": "PHP/8.2.0",
    }

    result = analyze_web_checks(
        status_code=200,
        headers=headers,
        url="https://example.com/",
    )

    assert any(
        observation["title"] == "Technology disclosure"
        for observation in result["observations"]
    )


def test_cors_wildcard_is_detected():
    headers = {
        "access-control-allow-origin": "*",
    }

    result = analyze_web_checks(
        status_code=200,
        headers=headers,
        url="https://example.com/",
    )

    assert any(
        observation["title"] == "Permissive CORS policy"
        for observation in result["observations"]
    )


def test_redirect_without_location_is_safe():
    result = analyze_web_checks(
        status_code=200,
        headers={},
        url="https://example.com/",
    )

    assert result["status_code"] == 200


def test_result_contains_expected_structure():
    result = analyze_web_checks(
        status_code=200,
        headers={},
        url="https://example.com/",
    )

    assert "observations" in result
    assert "observation_count" in result
    assert "high_count" in result
    assert "medium_count" in result
    assert "low_count" in result
    assert isinstance(result["observations"], list)
