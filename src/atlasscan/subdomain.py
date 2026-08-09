from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed


DEFAULT_SUBDOMAINS = [
    "www",
    "mail",
    "ftp",
    "api",
    "dev",
    "test",
    "staging",
    "admin",
    "portal",
    "app",
]


def resolve_subdomain(subdomain: str, target: str) -> dict | None:
    hostname = f"{subdomain}.{target}"

    try:
        addresses = socket.gethostbyname_ex(hostname)[2]

        if not addresses:
            return None

        return {
            "hostname": hostname,
            "addresses": list(dict.fromkeys(addresses)),
        }

    except (socket.gaierror, socket.herror, OSError):
        return None


def discover_subdomains(
    target: str,
    subdomains: list[str] | None = None,
    workers: int = 20,
) -> list[dict]:
    names = subdomains or DEFAULT_SUBDOMAINS
    results: list[dict] = []

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(resolve_subdomain, name, target): name
            for name in names
        }

        for future in as_completed(futures):
            result = future.result()

            if result is not None:
                results.append(result)

    results.sort(key=lambda item: item["hostname"])

    return results
