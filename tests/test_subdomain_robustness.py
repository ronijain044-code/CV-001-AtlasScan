from unittest.mock import Mock

import pytest

from src.atlasscan import subdomain


def test_resolve_subdomain_returns_expected_shape(monkeypatch):
    def fake_gethostbyname_ex(hostname):
        return (
            hostname,
            [],
            ["192.0.2.10", "192.0.2.11"],
        )

    monkeypatch.setattr(
        subdomain.socket,
        "gethostbyname_ex",
        fake_gethostbyname_ex,
    )

    result = subdomain.resolve_subdomain(
        "www",
        "example.com",
    )

    assert result == {
        "hostname": "www.example.com",
        "addresses": [
            "192.0.2.10",
            "192.0.2.11",
        ],
    }


def test_resolve_subdomain_deduplicates_addresses(monkeypatch):
    monkeypatch.setattr(
        subdomain.socket,
        "gethostbyname_ex",
        lambda hostname: (
            hostname,
            [],
            [
                "192.0.2.10",
                "192.0.2.10",
                "192.0.2.11",
            ],
        ),
    )

    result = subdomain.resolve_subdomain(
        "api",
        "example.com",
    )

    assert result["addresses"] == [
        "192.0.2.10",
        "192.0.2.11",
    ]


@pytest.mark.parametrize(
    "exception",
    [
        subdomain.socket.gaierror,
        subdomain.socket.herror,
        OSError,
    ],
)
def test_resolve_subdomain_handles_resolution_errors(
    monkeypatch,
    exception,
):
    def fail(*args, **kwargs):
        raise exception("resolution failed")

    monkeypatch.setattr(
        subdomain.socket,
        "gethostbyname_ex",
        fail,
    )

    result = subdomain.resolve_subdomain(
        "missing",
        "example.com",
    )

    assert result is None


def test_resolve_subdomain_returns_none_without_addresses(
    monkeypatch,
):
    monkeypatch.setattr(
        subdomain.socket,
        "gethostbyname_ex",
        lambda hostname: (
            hostname,
            [],
            [],
        ),
    )

    result = subdomain.resolve_subdomain(
        "empty",
        "example.com",
    )

    assert result is None


def test_discover_subdomains_uses_supplied_names(monkeypatch):
    calls = []

    def fake_resolve(name, target):
        calls.append((name, target))

        return {
            "hostname": f"{name}.{target}",
            "addresses": ["192.0.2.10"],
        }

    monkeypatch.setattr(
        subdomain,
        "resolve_subdomain",
        fake_resolve,
    )

    result = subdomain.discover_subdomains(
        "example.com",
        subdomains=["api", "www"],
    )

    assert calls == [
        ("api", "example.com"),
        ("www", "example.com"),
    ]

    assert result == [
        {
            "hostname": "api.example.com",
            "addresses": ["192.0.2.10"],
        },
        {
            "hostname": "www.example.com",
            "addresses": ["192.0.2.10"],
        },
    ]


def test_discover_subdomains_sorts_results(monkeypatch):
    def fake_resolve(name, target):
        return {
            "hostname": f"{name}.{target}",
            "addresses": ["192.0.2.10"],
        }

    monkeypatch.setattr(
        subdomain,
        "resolve_subdomain",
        fake_resolve,
    )

    result = subdomain.discover_subdomains(
        "example.com",
        subdomains=[
            "z",
            "api",
            "www",
            "mail",
        ],
    )

    assert [
        item["hostname"]
        for item in result
    ] == [
        "api.example.com",
        "mail.example.com",
        "www.example.com",
        "z.example.com",
    ]


def test_discover_subdomains_skips_missing_results(
    monkeypatch,
):
    def fake_resolve(name, target):
        if name == "missing":
            return None

        return {
            "hostname": f"{name}.{target}",
            "addresses": ["192.0.2.10"],
        }

    monkeypatch.setattr(
        subdomain,
        "resolve_subdomain",
        fake_resolve,
    )

    result = subdomain.discover_subdomains(
        "example.com",
        subdomains=[
            "www",
            "missing",
            "api",
        ],
    )

    assert [
        item["hostname"]
        for item in result
    ] == [
        "api.example.com",
        "www.example.com",
    ]


def test_discover_subdomains_empty_names_uses_defaults(
    monkeypatch,
):
    calls = []

    def fake_resolve(name, target):
        calls.append(name)
        return None

    monkeypatch.setattr(
        subdomain,
        "resolve_subdomain",
        fake_resolve,
    )

    result = subdomain.discover_subdomains(
        "example.com",
        subdomains=[],
    )

    assert result == []
    assert sorted(calls) == sorted(
        subdomain.DEFAULT_SUBDOMAINS
    )


def test_discover_subdomains_default_list_is_used(
    monkeypatch,
):
    calls = []

    def fake_resolve(name, target):
        calls.append(name)
        return None

    monkeypatch.setattr(
        subdomain,
        "resolve_subdomain",
        fake_resolve,
    )

    result = subdomain.discover_subdomains(
        "example.com",
    )

    assert result == []
    assert sorted(calls) == sorted(
        subdomain.DEFAULT_SUBDOMAINS
    )


def test_discover_subdomains_respects_worker_count(
    monkeypatch,
):
    created = {}

    class FakeExecutor:
        def __init__(self, max_workers):
            created["workers"] = max_workers

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def submit(self, function, *args):
            return FakeFuture(function, args)

    class FakeFuture:
        def __init__(self, function, args):
            self.function = function
            self.args = args

        def result(self):
            return self.function(*self.args)

    monkeypatch.setattr(
        subdomain,
        "ThreadPoolExecutor",
        FakeExecutor,
    )

    monkeypatch.setattr(
        subdomain,
        "as_completed",
        lambda futures: futures,
    )

    monkeypatch.setattr(
        subdomain,
        "resolve_subdomain",
        lambda name, target: None,
    )

    result = subdomain.discover_subdomains(
        "example.com",
        subdomains=["www", "api"],
        workers=7,
    )

    assert result == []
    assert created["workers"] == 7


def test_discover_subdomains_handles_duplicate_names(
    monkeypatch,
):
    calls = []

    def fake_resolve(name, target):
        calls.append(name)

        return {
            "hostname": f"{name}.{target}",
            "addresses": ["192.0.2.10"],
        }

    monkeypatch.setattr(
        subdomain,
        "resolve_subdomain",
        fake_resolve,
    )

    result = subdomain.discover_subdomains(
        "example.com",
        subdomains=[
            "www",
            "www",
            "api",
        ],
    )

    assert len(result) == 3
    assert calls.count("www") == 2
