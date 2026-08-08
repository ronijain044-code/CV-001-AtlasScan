from __future__ import annotations

import socket


def _unique(values: list[str]) -> list[str]:
    """Return values without duplicates while preserving order."""
    seen = set()
    result = []

    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)

    return result


def resolve_a(target: str) -> list[str]:
    """Resolve IPv4 A records."""
    try:
        addresses = []

        for result in socket.getaddrinfo(
            target,
            None,
            socket.AF_INET,
            socket.SOCK_STREAM,
        ):
            addresses.append(result[4][0])

        return _unique(addresses)

    except socket.gaierror:
        return []


def resolve_aaaa(target: str) -> list[str]:
    """Resolve IPv6 AAAA records."""
    try:
        addresses = []

        for result in socket.getaddrinfo(
            target,
            None,
            socket.AF_INET6,
            socket.SOCK_STREAM,
        ):
            addresses.append(result[4][0])

        return _unique(addresses)

    except socket.gaierror:
        return []


def resolve_ptr(address: str) -> list[str]:
    """Resolve a PTR record for an IP address."""
    try:
        hostname, aliases, addresses = socket.gethostbyaddr(address)

        return _unique(
            [hostname, *aliases]
        )

    except (socket.herror, socket.gaierror):
        return []


def reverse_dns(addresses: list[str]) -> dict[str, list[str]]:
    """Perform reverse DNS lookups for IPv4/IPv6 addresses."""
    results = {}

    for address in addresses:
        hostnames = resolve_ptr(address)

        if hostnames:
            results[address] = hostnames

    return results


def resolve_dns(target: str) -> dict:
    """
    Collect basic DNS intelligence for a target.

    The standard-library resolver provides A and AAAA records.
    Reverse DNS is performed against the discovered addresses.
    """
    a_records = resolve_a(target)
    aaaa_records = resolve_aaaa(target)

    all_addresses = _unique(
        [*a_records, *aaaa_records]
    )

    return {
        "a": a_records,
        "aaaa": aaaa_records,
        "ptr": reverse_dns(all_addresses),
    }
