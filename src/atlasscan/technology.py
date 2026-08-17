from __future__ import annotations

import re
from typing import Any


Technology = dict[str, str]


def _normalize(value: object) -> str:
    if value is None:
        return ""

    return str(value).strip()


def _lower(value: object) -> str:
    return _normalize(value).lower()


def _add(
    results: list[Technology],
    seen: set[tuple[str, str]],
    *,
    name: str,
    category: str,
    detected_from: str,
) -> None:
    """
    Add a technology while preventing duplicates.
    """

    name = name.strip()

    if not name:
        return

    key = (
        name.lower(),
        category.lower(),
    )

    if key in seen:
        return

    seen.add(key)

    results.append(
        {
            "name": name,
            "category": category,
            "detected_from": detected_from,
        }
    )


def _extract_version(
    value: str,
    product: str,
) -> str | None:
    """
    Extract a semantic-ish version from a product string.

    Examples:
        Apache/2.4.7
        nginx/1.24.0
        OpenSSH_9.6p1
    """

    if not value:
        return None

    pattern = re.compile(
        rf"{re.escape(product)}[\/_\s-]*"
        r"([0-9]+(?:\.[0-9]+)+(?:[A-Za-z0-9.-]*)?)",
        re.IGNORECASE,
    )

    match = pattern.search(value)

    if not match:
        return None

    return match.group(1)


def _technology_name(
    product: str,
    version: str | None,
) -> str:
    if version:
        return f"{product} {version}"

    return product


def _detect_server_header(
    server: str,
    results: list[Technology],
    seen: set[tuple[str, str]],
) -> None:
    """
    Detect web-server technologies from the Server header.
    """

    value = _normalize(server)

    if not value:
        return

    lower = value.lower()

    # Apache
    if "apache" in lower:
        version = _extract_version(value, "Apache")

        _add(
            results,
            seen,
            name=_technology_name("Apache", version),
            category="web-server",
            detected_from="server-header",
        )

    # nginx
    if "nginx" in lower:
        version = _extract_version(value, "nginx")

        _add(
            results,
            seen,
            name=_technology_name("Nginx", version),
            category="web-server",
            detected_from="server-header",
        )

    # Microsoft IIS
    if "microsoft-iis" in lower or "iis/" in lower:
        version = _extract_version(value, "IIS")

        _add(
            results,
            seen,
            name=_technology_name("Microsoft IIS", version),
            category="web-server",
            detected_from="server-header",
        )

    # Caddy
    if "caddy" in lower:
        version = _extract_version(value, "Caddy")

        _add(
            results,
            seen,
            name=_technology_name("Caddy", version),
            category="web-server",
            detected_from="server-header",
        )


def _detect_powered_by(
    powered_by: str,
    results: list[Technology],
    seen: set[tuple[str, str]],
) -> None:
    """
    Detect technologies from X-Powered-By.
    """

    value = _normalize(powered_by)

    if not value:
        return

    lower = value.lower()

    # PHP
    if "php" in lower:
        version = _extract_version(value, "PHP")

        _add(
            results,
            seen,
            name=_technology_name("PHP", version),
            category="runtime",
            detected_from="x-powered-by",
        )

    # Express
    if "express" in lower:
        _add(
            results,
            seen,
            name="Express",
            category="framework",
            detected_from="x-powered-by",
        )

    # ASP.NET
    if "asp.net" in lower:
        _add(
            results,
            seen,
            name="ASP.NET",
            category="framework",
            detected_from="x-powered-by",
        )

    # Node.js
    if "node" in lower or "node.js" in lower:
        _add(
            results,
            seen,
            name="Node.js",
            category="runtime",
            detected_from="x-powered-by",
        )


def _detect_banner(
    banner: str,
    results: list[Technology],
    seen: set[tuple[str, str]],
) -> None:
    """
    Detect technologies from service banners.
    """

    value = _normalize(banner)

    if not value:
        return

    lower = value.lower()

    # OpenSSH
    if "openssh" in lower:
        match = re.search(
            r"OpenSSH[_/\s-]*"
            r"([0-9]+(?:\.[0-9]+)+(?:p[0-9]+)?)",
            value,
            re.IGNORECASE,
        )

        version = match.group(1) if match else None

        _add(
            results,
            seen,
            name=_technology_name("OpenSSH", version),
            category="remote-access",
            detected_from="banner",
        )

    # Apache
    if "apache/" in lower or "apache " in lower:
        version = _extract_version(value, "Apache")

        _add(
            results,
            seen,
            name=_technology_name("Apache", version),
            category="web-server",
            detected_from="banner",
        )

    # nginx
    if "nginx/" in lower:
        version = _extract_version(value, "nginx")

        _add(
            results,
            seen,
            name=_technology_name("Nginx", version),
            category="web-server",
            detected_from="banner",
        )

    # IIS
    if "microsoft-iis" in lower:
        _add(
            results,
            seen,
            name="Microsoft IIS",
            category="web-server",
            detected_from="banner",
        )


def _detect_html(
    html_body: str,
    title: str | None,
    results: list[Technology],
    seen: set[tuple[str, str]],
) -> None:
    """
    Detect common web technologies from HTML.

    This uses simple signatures rather than executing JavaScript.
    """

    body = _normalize(html_body)

    if not body:
        return

    lower = body.lower()

    normalized_title = _lower(title)

    # WordPress
    wordpress_signatures = (
        "wp-content/",
        "wp-includes/",
        "wordpress",
        "wp-json",
    )

    if any(
        signature in lower
        for signature in wordpress_signatures
    ):
        _add(
            results,
            seen,
            name="WordPress",
            category="cms",
            detected_from="html",
        )

    # React
    react_signatures = (
        "reactroot",
        "__reactfiber",
        "data-reactroot",
        "react-dom",
        "react.production",
        "react.development",
        "react.min.js",
    )

    if any(
        signature in lower
        for signature in react_signatures
    ):
        _add(
            results,
            seen,
            name="React",
            category="frontend",
            detected_from="html",
        )

    # Next.js
    next_signatures = (
        "__next_data__",
        "/_next/",
        "__next_f",
    )

    if any(
        signature in lower
        for signature in next_signatures
    ):
        _add(
            results,
            seen,
            name="Next.js",
            category="framework",
            detected_from="html",
        )

        _add(
            results,
            seen,
            name="React",
            category="frontend",
            detected_from="html",
        )

    # jQuery
    if re.search(
        r"(?:jquery(?:[-.]|\s)|jquery\.min\.js)",
        lower,
    ):
        _add(
            results,
            seen,
            name="jQuery",
            category="javascript-library",
            detected_from="html",
        )

    # Bootstrap
    if (
        "bootstrap.min.css" in lower
        or "bootstrap.css" in lower
        or "bootstrap.min.js" in lower
        or "bootstrap.js" in lower
        or "bootstrap" in normalized_title
    ):
        _add(
            results,
            seen,
            name="Bootstrap",
            category="frontend-framework",
            detected_from="html",
        )

    # Django
    if (
        "csrfmiddlewaretoken" in lower
        or "django" in lower
    ):
        _add(
            results,
            seen,
            name="Django",
            category="framework",
            detected_from="html",
        )

    # Flask
    if "flask" in lower:
        _add(
            results,
            seen,
            name="Flask",
            category="framework",
            detected_from="html",
        )

    # Laravel
    if (
        "laravel" in lower
        or "laravel_session" in lower
    ):
        _add(
            results,
            seen,
            name="Laravel",
            category="framework",
            detected_from="html",
        )


def fingerprint_technology(
    *,
    service: str | None = None,
    version: str | None = None,
    banner: str | None = None,
    http_details: dict[str, Any] | None = None,
) -> list[Technology]:
    """
    Fingerprint technologies using passive service and HTTP evidence.

    Sources include:

    - service identification
    - service version
    - network banner
    - HTTP Server header
    - X-Powered-By
    - HTTP headers
    - HTML response body
    - HTML title

    Returns a list of dictionaries containing:

        name
        category
        detected_from
    """

    results: list[Technology] = []
    seen: set[tuple[str, str]] = set()

    service_name = _normalize(service)
    service_lower = service_name.lower()

    service_version = _normalize(version)

    banner_value = _normalize(banner)

    http = http_details or {}

    # ---------------------------------------------------------
    # Service-level detection
    # ---------------------------------------------------------

    if service_lower == "ssh":
        if service_version and service_version != "unknown":
            _add(
                results,
                seen,
                name=f"OpenSSH {service_version}",
                category="remote-access",
                detected_from="service-version",
            )
        elif "openssh" in banner_value.lower():
            _detect_banner(
                banner_value,
                results,
                seen,
            )

    if service_lower == "http":
        if (
            service_version
            and service_version != "unknown"
            and "apache" in service_version.lower()
        ):
            _add(
                results,
                seen,
                name=f"Apache {service_version.split()[-1]}",
                category="web-server",
                detected_from="service-version",
            )

    # ---------------------------------------------------------
    # Banner detection
    # ---------------------------------------------------------

    _detect_banner(
        banner_value,
        results,
        seen,
    )

    # ---------------------------------------------------------
    # HTTP detection
    # ---------------------------------------------------------

    if http:
        server = http.get("server")

        if server:
            _detect_server_header(
                str(server),
                results,
                seen,
            )

        powered_by = (
            http.get("x-powered-by")
            or http.get("X-Powered-By")
        )

        headers = http.get("headers")

        if isinstance(headers, dict):
            powered_by = (
                powered_by
                or headers.get("x-powered-by")
                or headers.get("X-Powered-By")
            )

            server = (
                server
                or headers.get("server")
                or headers.get("Server")
            )

            if server:
                _detect_server_header(
                    str(server),
                    results,
                    seen,
                )

        if powered_by:
            _detect_powered_by(
                str(powered_by),
                results,
                seen,
            )

        # -----------------------------------------------------
        # Optional HTML body/title
        # -----------------------------------------------------

        body = (
            http.get("body")
            or http.get("html")
            or http.get("content")
        )

        title = http.get("title")

        if body:
            _detect_html(
                str(body),
                str(title) if title else None,
                results,
                seen,
            )

    return results
