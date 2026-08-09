from __future__ import annotations

from typing import Any


SECURITY_HEADER_RULES = {
    "Content-Security-Policy": {
        "severity": "high",
        "description": (
            "Content-Security-Policy helps control which resources "
            "a browser is allowed to load."
        ),
    },
    "Strict-Transport-Security": {
        "severity": "medium",
        "description": (
            "HSTS instructs browsers to use HTTPS for future requests."
        ),
    },
    "X-Frame-Options": {
        "severity": "medium",
        "description": (
            "X-Frame-Options helps protect against clickjacking."
        ),
    },
    "X-Content-Type-Options": {
        "severity": "low",
        "description": (
            "X-Content-Type-Options helps prevent MIME-type sniffing."
        ),
    },
    "Referrer-Policy": {
        "severity": "low",
        "description": (
            "Referrer-Policy controls how much referrer information "
            "is sent with requests."
        ),
    },
    "Permissions-Policy": {
        "severity": "low",
        "description": (
            "Permissions-Policy controls access to selected browser "
            "features."
        ),
    },
}


def _normalize_headers(headers: dict[str, Any] | None) -> dict[str, str]:
    """
    Normalize HTTP header names to lowercase.

    This allows security analysis to work with either lowercase
    or conventional HTTP header capitalization.
    """
    if not headers:
        return {}

    return {
        str(key).lower(): str(value)
        for key, value in headers.items()
        if value is not None
    }


def analyze_security_headers(
    headers: dict[str, Any] | None,
) -> dict[str, Any]:
    """
    Analyze common HTTP security headers.

    Returns:
        {
            "headers": {...},
            "present_count": int,
            "missing_count": int,
            "total_count": int,
            "missing": [...],
            "observations": [...]
        }
    """
    normalized = _normalize_headers(headers)

    header_results: dict[str, dict[str, Any]] = {}
    missing: list[str] = []
    observations: list[dict[str, Any]] = []

    for header_name, rule in SECURITY_HEADER_RULES.items():
        value = normalized.get(header_name.lower())

        present = value is not None and value.strip() != ""

        header_results[header_name] = {
            "present": present,
            "value": value,
        }

        if not present:
            missing.append(header_name)

            observations.append(
                {
                    "severity": rule["severity"],
                    "title": f"Missing {header_name}",
                    "description": rule["description"],
                    "evidence": f"{header_name} header was not observed.",
                }
            )

    return {
        "headers": header_results,
        "present_count": len(SECURITY_HEADER_RULES) - len(missing),
        "missing_count": len(missing),
        "total_count": len(SECURITY_HEADER_RULES),
        "missing": missing,
        "observations": observations,
    }


def analyze_https(
    target: str,
    http_details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Analyze basic HTTPS information from existing web inspection data.

    This function does not perform an additional request.
    """
    details = http_details or {}

    url = str(details.get("url") or "")
    final_url = str(details.get("final_url") or "")
    redirect = bool(details.get("redirect"))

    uses_https = (
        url.lower().startswith("https://")
        or final_url.lower().startswith("https://")
    )

    return {
        "uses_https": uses_https,
        "url": url or None,
        "final_url": final_url or None,
        "redirect": redirect,
    }


def analyze_cookies(
    headers: dict[str, Any] | None,
) -> dict[str, Any]:
    """
    Perform a passive analysis of Set-Cookie response headers.

    The function does not modify cookies or send additional requests.
    """
    if not headers:
        return {
            "cookies": [],
            "count": 0,
            "observations": [],
        }

    cookie_values: list[str] = []

    for key, value in headers.items():
        if str(key).lower() != "set-cookie":
            continue

        if isinstance(value, (list, tuple)):
            cookie_values.extend(str(item) for item in value)
        elif value is not None:
            cookie_values.append(str(value))

    cookies: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []

    for raw_cookie in cookie_values:
        parts = [
            part.strip()
            for part in raw_cookie.split(";")
            if part.strip()
        ]

        if not parts:
            continue

        name = parts[0].split("=", 1)[0].strip()

        attributes = {
            part.split("=", 1)[0].strip().lower()
            for part in parts[1:]
        }

        secure = "secure" in attributes
        httponly = "httponly" in attributes
        samesite = any(
            attribute.startswith("samesite")
            for attribute in attributes
        )

        cookie = {
            "name": name,
            "secure": secure,
            "httponly": httponly,
            "samesite": samesite,
        }

        cookies.append(cookie)

        if not secure:
            observations.append(
                {
                    "severity": "medium",
                    "title": f"Cookie {name} missing Secure flag",
                    "description": (
                        "The cookie was observed without the Secure "
                        "attribute."
                    ),
                    "evidence": raw_cookie,
                }
            )

        if not httponly:
            observations.append(
                {
                    "severity": "low",
                    "title": f"Cookie {name} missing HttpOnly flag",
                    "description": (
                        "The cookie was observed without the HttpOnly "
                        "attribute."
                    ),
                    "evidence": raw_cookie,
                }
            )

        if not samesite:
            observations.append(
                {
                    "severity": "low",
                    "title": f"Cookie {name} missing SameSite attribute",
                    "description": (
                        "The cookie was observed without a SameSite "
                        "attribute."
                    ),
                    "evidence": raw_cookie,
                }
            )

    return {
        "cookies": cookies,
        "count": len(cookies),
        "observations": observations,
    }


def analyze_web_security(
    web_details: dict[str, Any] | None,
) -> dict[str, Any]:
    """
    Run passive security analysis against an existing web-inspection
    result.

    No exploitation or intrusive requests are performed.
    """
    details = web_details or {}

    headers = details.get("headers") or {}

    header_analysis = analyze_security_headers(headers)
    cookie_analysis = analyze_cookies(headers)
    https_analysis = analyze_https(
        target="",
        http_details=details,
    )

    observations = (
        header_analysis["observations"]
        + cookie_analysis["observations"]
    )

    return {
        "security_headers": header_analysis,
        "cookies": cookie_analysis,
        "https": https_analysis,
        "observations": observations,
        "observation_count": len(observations),
    }
