import socket

from src.atlasscan import scanner


def test_scan_port_returns_false_on_socket_error(monkeypatch):
    class FakeSocket:
        def settimeout(self, timeout):
            pass

        def connect_ex(self, address):
            raise socket.error("connection failed")

        def close(self):
            pass

    monkeypatch.setattr(
        scanner.socket,
        "socket",
        lambda *args, **kwargs: FakeSocket(),
    )

    assert scanner.scan_port("example.com", 80) is False


def test_scan_port_returns_false_on_timeout(monkeypatch):
    class FakeSocket:
        def settimeout(self, timeout):
            pass

        def connect_ex(self, address):
            raise socket.timeout()

        def close(self):
            pass

    monkeypatch.setattr(
        scanner.socket,
        "socket",
        lambda *args, **kwargs: FakeSocket(),
    )

    assert scanner.scan_port("example.com", 80) is False


def test_scan_port_closes_socket(monkeypatch):
    state = {"closed": False}

    class FakeSocket:
        def settimeout(self, timeout):
            pass

        def connect_ex(self, address):
            return 1

        def close(self):
            state["closed"] = True

    monkeypatch.setattr(
        scanner.socket,
        "socket",
        lambda *args, **kwargs: FakeSocket(),
    )

    result = scanner.scan_port("example.com", 80)

    assert result is False
    assert state["closed"] is True


def test_scan_port_returns_true_when_connection_succeeds(monkeypatch):
    class FakeSocket:
        def settimeout(self, timeout):
            pass

        def connect_ex(self, address):
            return 0

        def close(self):
            pass

    monkeypatch.setattr(
        scanner.socket,
        "socket",
        lambda *args, **kwargs: FakeSocket(),
    )

    assert scanner.scan_port("example.com", 80) is True


def test_scan_ports_with_empty_list_returns_empty():
    result = scanner.scan_ports(
        "example.com",
        [],
    )

    assert result == []


def test_scan_ports_returns_sorted_results(monkeypatch):
    def fake_scan_port(host, port, timeout):
        return port in {80, 22, 443}

    monkeypatch.setattr(
        scanner,
        "scan_port",
        fake_scan_port,
    )

    result = scanner.scan_ports(
        "example.com",
        [443, 80, 22],
    )

    assert result == [22, 80, 443]


def test_scan_ports_only_returns_open_ports(monkeypatch):
    def fake_scan_port(host, port, timeout):
        return port in {22, 443}

    monkeypatch.setattr(
        scanner,
        "scan_port",
        fake_scan_port,
    )

    result = scanner.scan_ports(
        "example.com",
        [21, 22, 80, 443],
    )

    assert result == [22, 443]


def test_scan_ports_respects_worker_limit(monkeypatch):
    observed = {}

    class FakeExecutor:
        def __init__(self, max_workers):
            observed["workers"] = max_workers

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            pass

        def map(self, function, ports):
            return [
                function(port)
                for port in ports
            ]

    monkeypatch.setattr(
        scanner,
        "ThreadPoolExecutor",
        FakeExecutor,
    )

    monkeypatch.setattr(
        scanner,
        "scan_port",
        lambda host, port, timeout: True,
    )

    result = scanner.scan_ports(
        "example.com",
        [80, 443, 22],
        workers=2,
    )

    assert observed["workers"] == 2
    assert result == [22, 80, 443]


def test_scan_ports_caps_workers_to_number_of_ports(monkeypatch):
    observed = {}

    class FakeExecutor:
        def __init__(self, max_workers):
            observed["workers"] = max_workers

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            pass

        def map(self, function, ports):
            return [
                function(port)
                for port in ports
            ]

    monkeypatch.setattr(
        scanner,
        "ThreadPoolExecutor",
        FakeExecutor,
    )

    monkeypatch.setattr(
        scanner,
        "scan_port",
        lambda host, port, timeout: True,
    )

    scanner.scan_ports(
        "example.com",
        [80, 443],
        workers=100,
    )

    assert observed["workers"] == 2
