from __future__ import annotations

from typing import Any
from urllib.parse import urlparse


SEVERITIES = {
    "high",
    "medium",
    "low",
}


def _observation(
    severity: str,
    title: str,
    description: str,
    evidence: str,
) -> dict[str, Any]:
    return {
        "severity": severity,
        "title": title,
        "description": description,
        "evidence": evidence,
    }


def _count_severities(
    observations: list[dict[str, Any]],
) -> dict[str, int]:
    counts = {
        "high": 0,
        "medium": 0,
        "low": 0,
    }

    for observation in observations:
        severity = str(
            observation.get("severity", "")
        ).lower()

        if severity in SEVERITIES:
            counts[severity] += 1

    return counts


def analyze_web_checks(
    status_code: int,
    headers: dict[str, Any] | None,
    url: str,
) -> dict[str, Any]:
    """
    Perform passive web-security configuration checks.

    This function analyzes the supplied HTTP response only.
    It does not exploit the target or send attack payloads.
    """

    headers = headers or {}

    normalized_headers = {
        str(key).lower(): str(value)
        for key, value in headers.items()
    }

    observations: list[dict[str, Any]] = []

    parsed = urlparse(url)

    if parsed.scheme.lower() == "http":
        observations.append(
            _observation(
                "medium",
                "HTTP instead of HTTPS",
                "The inspected URL uses HTTP instead of HTTPS.",
                f"URL scheme: {parsed.scheme}",
            )
        )

    if (
        parsed.scheme.lower() == "https"
        and "strict-transport-security"
        not in normalized_headers
    ):
        observations.append(
            _observation(
                "medium",
                "Missing Strict-Transport-Security",
                "The HTTPS response did not include an HSTS header.",
                "Strict-Transport-Security header was not observed.",
            )
        )

    if "content-security-policy" not in normalized_headers:
        observations.append(
            _observation(
                "high",
                "Missing Content-Security-Policy",
                "The response did not include a Content-Security-Policy header.",
                "Content-Security-Policy header was not observed.",
            )
        )

    if "x-frame-options" not in normalized_headers:
        observations.append(
            _observation(
                "medium",
                "Missing X-Frame-Options",
                "The response did not include an X-Frame-Options header.",
                "X-Frame-Options header was not observed.",
            )
        )

    if "x-content-type-options" not in normalized_headers:
        observations.append(
            _observation(
                "low",
                "Missing X-Content-Type-Options",
                "The response did not include an X-Content-Type-Options header.",
                "X-Content-Type-Options header was not observed.",
            )
        )

    if "referrer-policy" not in normalized_headers:
        observations.append(
            _observation(
                "low",
                "Missing Referrer-Policy",
                "The response did not include a Referrer-Policy header.",
                "Referrer-Policy header was not observed.",
            )
        )

    if "permissions-policy" not in normalized_headers:
        observations.append(
            _observation(
                "low",
                "Missing Permissions-Policy",
                "The response did not include a Permissions-Policy header.",
                "Permissions-Policy header was not observed.",
            )
        )

    server = normalized_headers.get("server", "")

    if server and any(
        character.isdigit()
        for character in server
    ):
        observations.append(
            _observation(
                "low",
                "Server version disclosure",
                "The Server response header appears to disclose version information.",
                f"Server: {server}",
            )
        )

    powered_by = normalized_headers.get(
        "x-powered-by",
        "",
    )

    if powered_by:
        observations.append(
            _observation(
                "low",
                "Technology disclosure",
                "The response exposes technology information through X-Powered-By.",
                f"X-Powered-By: {powered_by}",
            )
        )

    cors = normalized_headers.get(
        "access-control-allow-origin",
        "",
    )

    if cors.strip() == "*":
        observations.append(
            _observation(
                "medium",
                "Permissive CORS policy",
                "The response allows cross-origin requests from any origin.",
                "Access-Control-Allow-Origin: *",
            )
        )

    set_cookie = normalized_headers.get(
        "set-cookie",
        "",
    )

    if set_cookie:
        cookie_lower = set_cookie.lower()

        if "secure" not in cookie_lower:
            observations.append(
                _observation(
                    "medium",
                    "Cookie missing Secure flag",
                    "A Set-Cookie response does not include the Secure attribute.",
                    f"Set-Cookie: {set_cookie}",
                )
            )

        if "httponly" not in cookie_lower:
            observations.append(
                _observation(
                    "low",
                    "Cookie missing HttpOnly flag",
                    "A Set-Cookie response does not include the HttpOnly attribute.",
                    f"Set-Cookie: {set_cookie}",
                )
            )

        if "samesite" not in cookie_lower:
            observations.append(
                _observation(
                    "low",
                    "Cookie missing SameSite attribute",
                    "A Set-Cookie response does not include a SameSite attribute.",
                    f"Set-Cookie: {set_cookie}",
                )
            )

    counts = _count_severities(
        observations
    )

    return {
        "status_code": status_code,
        "url": url,
        "observations": observations,
        "observation_count": len(observations),
        "high_count": counts["high"],
        "medium_count": counts["medium"],
        "low_count": counts["low"],
    }
