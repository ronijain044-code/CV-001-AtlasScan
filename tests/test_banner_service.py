import socket

from src.atlasscan import banner
from src.atlasscan.service import identify_service


def test_grab_banner_returns_banner(monkeypatch):
    class FakeSocket:
        def settimeout(self, timeout):
            self.timeout = timeout

        def connect(self, address):
            self.address = address

        def recv(self, size):
            return b"SSH-2.0-OpenSSH_9.0\r\n"

        def close(self):
            pass

    monkeypatch.setattr(
        banner.socket,
        "socket",
        lambda *args, **kwargs: FakeSocket(),
    )

    result = banner.grab_banner(
        "example.com",
        22,
    )

    assert result == "SSH-2.0-OpenSSH_9.0"


def test_grab_banner_returns_none_on_empty_response(monkeypatch):
    class FakeSocket:
        def settimeout(self, timeout):
            pass

        def connect(self, address):
            pass

        def recv(self, size):
            return b""

        def close(self):
            pass

    monkeypatch.setattr(
        banner.socket,
        "socket",
        lambda *args, **kwargs: FakeSocket(),
    )

    result = banner.grab_banner(
        "example.com",
        22,
    )

    assert result is None


def test_grab_banner_returns_none_on_timeout(monkeypatch):
    class FakeSocket:
        def settimeout(self, timeout):
            pass

        def connect(self, address):
            raise socket.timeout()

        def close(self):
            pass

    monkeypatch.setattr(
        banner.socket,
        "socket",
        lambda *args, **kwargs: FakeSocket(),
    )

    result = banner.grab_banner(
        "example.com",
        22,
    )

    assert result is None


def test_grab_banner_returns_none_on_socket_error(monkeypatch):
    class FakeSocket:
        def settimeout(self, timeout):
            pass

        def connect(self, address):
            raise socket.error("connection failed")

        def close(self):
            pass

    monkeypatch.setattr(
        banner.socket,
        "socket",
        lambda *args, **kwargs: FakeSocket(),
    )

    result = banner.grab_banner(
        "example.com",
        22,
    )

    assert result is None


def test_grab_banner_closes_socket(monkeypatch):
    state = {"closed": False}

    class FakeSocket:
        def settimeout(self, timeout):
            pass

        def connect(self, address):
            pass

        def recv(self, size):
            return b"FTP Service Ready"

        def close(self):
            state["closed"] = True

    monkeypatch.setattr(
        banner.socket,
        "socket",
        lambda *args, **kwargs: FakeSocket(),
    )

    result = banner.grab_banner(
        "example.com",
        21,
    )

    assert result == "FTP Service Ready"
    assert state["closed"] is True


def test_grab_banner_sends_http_head_request(monkeypatch):
    state = {}

    class FakeSocket:
        def settimeout(self, timeout):
            pass

        def connect(self, address):
            state["address"] = address

        def sendall(self, data):
            state["request"] = data.decode("ascii")

        def recv(self, size):
            return b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.7\r\n"

        def close(self):
            pass

    monkeypatch.setattr(
        banner.socket,
        "socket",
        lambda *args, **kwargs: FakeSocket(),
    )

    result = banner.grab_banner(
        "example.com",
        80,
    )

    assert result.startswith("HTTP/1.1 200 OK")
    assert state["address"] == ("example.com", 80)
    assert "HEAD / HTTP/1.1" in state["request"]
    assert "Host: example.com" in state["request"]
    assert "Connection: close" in state["request"]


def test_identify_service_by_port():
    assert identify_service(21, None) == {
        "service": "ftp",
        "version": "unknown",
    }

    assert identify_service(22, None) == {
        "service": "ssh",
        "version": "unknown",
    }

    assert identify_service(80, None) == {
        "service": "http",
        "version": "unknown",
    }


def test_identify_unknown_port():
    result = identify_service(
        12345,
        None,
    )

    assert result == {
        "service": "unknown",
        "version": "unknown",
    }


def test_identify_openssh_version():
    result = identify_service(
        22,
        "SSH-2.0-OpenSSH_9.0 Ubuntu",
    )

    assert result["service"] == "ssh"
    assert result["version"] == "9.0"


def test_identify_apache_version():
    result = identify_service(
        80,
        "HTTP/1.1 200 OK\r\nServer: Apache/2.4.7 (Ubuntu)",
    )

    assert result["service"] == "http"
    assert result["version"] == "2.4.7"


def test_identify_nginx_version():
    result = identify_service(
        80,
        "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0",
    )

    assert result["service"] == "http"
    assert result["version"] == "1.24.0"


def test_identify_mysql_version():
    result = identify_service(
        3306,
        "MySQL 8.0.36",
    )

    assert result["service"] == "mysql"
    assert result["version"] == "8.0.36"


def test_identify_postgresql():
    result = identify_service(
        5432,
        "PostgreSQL database server",
    )

    assert result["service"] == "postgresql"
    assert result["version"] == "unknown"


def test_http_banner_without_server_version():
    result = identify_service(
        80,
        "HTTP/1.1 200 OK",
    )

    assert result["service"] == "http"
    assert result["version"] == "unknown"


def test_banner_detection_overrides_port_mapping():
    result = identify_service(
        8080,
        "SSH-2.0-OpenSSH_9.2",
    )

    assert result["service"] == "ssh"
    assert result["version"] == "9.2"


def test_empty_banner_uses_port_mapping():
    result = identify_service(
        443,
        "",
    )

    assert result == {
        "service": "https",
        "version": "unknown",
    }
