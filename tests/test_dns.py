import socket

from src.atlasscan.dns import (
    resolve_a,
    resolve_aaaa,
    resolve_ptr,
    reverse_dns,
    resolve_dns,
)


def test_resolve_a_missing_host_returns_empty_list():
    result = resolve_a("definitely-does-not-exist-123456.invalid")

    assert result == []


def test_resolve_aaaa_missing_host_returns_empty_list():
    result = resolve_aaaa("definitely-does-not-exist-123456.invalid")

    assert result == []


def test_resolve_ptr_invalid_address_returns_empty_list():
    result = resolve_ptr("192.0.2.999")

    assert result == []


def test_reverse_dns_empty_input_returns_empty_dict():
    result = reverse_dns([])

    assert result == {}


def test_reverse_dns_skips_failed_lookups(monkeypatch):
    def fake_resolve_ptr(address):
        if address == "192.0.2.1":
            return ["example.com"]

        return []

    monkeypatch.setattr(
        "src.atlasscan.dns.resolve_ptr",
        fake_resolve_ptr,
    )

    result = reverse_dns(
        ["192.0.2.1", "192.0.2.2"]
    )

    assert result == {
        "192.0.2.1": ["example.com"]
    }


def test_resolve_dns_returns_expected_shape():
    result = resolve_dns("scanme.nmap.org")

    assert isinstance(result, dict)
    assert "a" in result
    assert "aaaa" in result
    assert "ptr" in result

    assert isinstance(result["a"], list)
    assert isinstance(result["aaaa"], list)
    assert isinstance(result["ptr"], dict)


def test_resolve_dns_missing_host_returns_empty_sections():
    result = resolve_dns(
        "definitely-does-not-exist-123456.invalid"
    )

    assert result == {
        "a": [],
        "aaaa": [],
        "ptr": {},
    }


def test_resolve_a_deduplicates_addresses(monkeypatch):
    def fake_getaddrinfo(*args, **kwargs):
        return [
            (None, None, None, None, ("192.0.2.1", 0)),
            (None, None, None, None, ("192.0.2.1", 0)),
            (None, None, None, None, ("192.0.2.2", 0)),
        ]

    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        fake_getaddrinfo,
    )

    result = resolve_a("example.com")

    assert result == [
        "192.0.2.1",
        "192.0.2.2",
    ]
