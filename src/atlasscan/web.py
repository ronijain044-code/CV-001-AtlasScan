from __future__ import annotations

from typing import Any
from urllib.parse import urljoin
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError


DEFAULT_TIMEOUT = 3.0

SECURITY_HEADERS = {
    "content-security-policy": "Content-Security-Policy",
    "strict-transport-security": "Strict-Transport-Security",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}


def _normalize_url(target: str, port: int = 80) -> str:
    """
    Build a HTTP URL from a target and port.

    Port 443 uses HTTPS. All other ports use HTTP.
    """
    target = target.strip()

    if target.startswith(("http://", "https://")):
        return target

    scheme = "https" if port == 443 else "http"
    return f"{scheme}://{target}:{port}"


def _request(
    url: str,
    timeout: float = DEFAULT_TIMEOUT,
    method: str = "GET",
) -> dict[str, Any]:
    """
    Perform a HTTP request and return normalized response information.
    """
    request = Request(
        url,
        headers={
            "User-Agent": "AtlasScan/1.0",
            "Accept": "*/*",
        },
        method=method,
    )

    try:
        with urlopen(
            request,
            timeout=timeout,
            context=None,
        ) as response:
            headers = {
                key.lower(): value
                for key, value in response.headers.items()
            }

            body = b""

            if method != "HEAD":
                body = response.read(1024 * 1024)

            return {
                "status_code": response.status,
                "url": response.geturl(),
                "headers": headers,
                "body": body,
                "error": None,
            }

    except HTTPError as exc:
        headers = {
            key.lower(): value
            for key, value in exc.headers.items()
        }

        body = b""

        try:
            body = exc.read(1024 * 1024)
        except Exception:
            pass

        return {
            "status_code": exc.code,
            "url": exc.geturl(),
            "headers": headers,
            "body": body,
            "error": None,
        }

    except (URLError, TimeoutError, OSError) as exc:
        return {
            "status_code": None,
            "url": url,
            "headers": {},
            "body": b"",
            "error": str(exc),
        }

    except Exception as exc:
        return {
            "status_code": None,
            "url": url,
            "headers": {},
            "body": b"",
            "error": str(exc),
        }


def _decode_body(body: bytes) -> str:
    """
    Safely decode an HTTP response body.
    """
    if not body:
        return ""

    try:
        return body.decode("utf-8", errors="replace")
    except Exception:
        return ""


def _extract_title(body: str) -> str | None:
    """
    Extract the HTML <title> value.
    """
    if not body:
        return None

    lower_body = body.lower()

    start = lower_body.find("<title")

    if start == -1:
        return None

    opening_end = lower_body.find(">", start)

    if opening_end == -1:
        return None

    closing_start = lower_body.find("</title>", opening_end)

    if closing_start == -1:
        return None

    title = body[opening_end + 1 : closing_start]

    title = " ".join(title.split())

    return title or None


def _security_headers(headers: dict[str, str]) -> dict[str, str | None]:
    """
    Extract common security-related HTTP headers.
    """
    result: dict[str, str | None] = {}

    for key, display_name in SECURITY_HEADERS.items():
        result[display_name] = headers.get(key)

    return result


def inspect_web(
    target: str,
    port: int = 80,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """
    Perform HTTP reconnaissance against a target.

    Returns:
        A dictionary containing:

        - status_code
        - url
        - final_url
        - title
        - server
        - content_type
        - content_length
        - allow
        - location
        - redirect
        - headers
        - security_headers
        - error
    """
    url = _normalize_url(target, port)

    response = _request(
        url=url,
        timeout=timeout,
        method="GET",
    )

    headers = response["headers"]

    final_url = response["url"]

    location = headers.get("location")

    redirect = final_url != url or (
        location is not None
        and response["status_code"] is not None
        and 300 <= response["status_code"] < 400
    )

    body = _decode_body(response["body"])

    content_length = headers.get("content-length")

    if content_length is not None:
        try:
            content_length_value: int | None = int(content_length)
        except ValueError:
            content_length_value = None
    else:
        content_length_value = None

    return {
        "status_code": response["status_code"],
        "url": url,
        "final_url": final_url,
        "title": _extract_title(body),
        "server": headers.get("server"),
        "content_type": headers.get("content-type"),
        "content_length": content_length_value,
        "allow": headers.get("allow"),
        "location": location,
        "redirect": redirect,
        "headers": headers,
        "security_headers": _security_headers(headers),
        "error": response["error"],
    }


def check_robots(
    target: str,
    port: int = 80,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """
    Check whether robots.txt exists and return its contents.
    """
    base_url = _normalize_url(target, port)
    robots_url = urljoin(base_url.rstrip("/") + "/", "robots.txt")

    response = _request(
        url=robots_url,
        timeout=timeout,
        method="GET",
    )

    body = _decode_body(response["body"])

    return {
        "url": robots_url,
        "status_code": response["status_code"],
        "exists": (
            response["status_code"] is not None
            and 200 <= response["status_code"] < 400
        ),
        "content": body if body else None,
        "error": response["error"],
    }


def discover_common_paths(
    target: str,
    port: int = 80,
    timeout: float = DEFAULT_TIMEOUT,
) -> list[dict[str, Any]]:
    """
    Check a small set of common, non-destructive web paths.

    This is intentionally limited to simple GET requests.
    """
    base_url = _normalize_url(target, port)

    common_paths = [
        "/",
        "/robots.txt",
        "/sitemap.xml",
        "/favicon.ico",
        "/.well-known/",
    ]

    discovered: list[dict[str, Any]] = []

    for path in common_paths:
        url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))

        response = _request(
            url=url,
            timeout=timeout,
            method="GET",
        )

        status_code = response["status_code"]

        if status_code is None:
            continue

        if 200 <= status_code < 400:
            discovered.append(
                {
                    "path": path,
                    "url": url,
                    "status_code": status_code,
                    "content_type": response["headers"].get(
                        "content-type"
                    ),
                    "content_length": response["headers"].get(
                        "content-length"
                    ),
                }
            )

    return discovered
