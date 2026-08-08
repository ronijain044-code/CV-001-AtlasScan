import json

from src.atlasscan.banner import grab_banner
from src.atlasscan.http import inspect_http
from src.atlasscan.scanner import scan_port, scan_ports
from src.atlasscan.service import identify_service
from src.atlasscan.technology import fingerprint_technology


def test_returns_boolean():
    result = scan_port("scanme.nmap.org", 80)
    assert isinstance(result, bool)


def test_scan_ports_returns_list():
    ports = scan_ports("scanme.nmap.org", [22, 80])
    assert isinstance(ports, list)


def test_scan_ports_returns_sorted_list():
    ports = scan_ports("scanme.nmap.org", [80, 22])
    assert ports == sorted(ports)


def test_json_report_structure(tmp_path):
    report = {
        "atlas_scan": {
            "version": "1.0",
            "target": "scanme.nmap.org",
            "ports_scanned": 3,
            "open_ports": [22, 80],
            "open_port_count": 2,
            "banners": {
                "22": "SSH-2.0-OpenSSH",
                "80": "HTTP/1.1 200 OK",
            },
            "services": {
                "22": {
                    "service": "ssh",
                    "version": "6.6.1p1",
                },
                "80": {
                    "service": "http",
                    "version": "2.4.7",
                },
            },
            "http": {
                "80": {
                    "status_code": 200,
                    "server": "Apache/2.4.7 (Ubuntu)",
                    "content_type": "text/html",
                    "content_length": None,
                    "allow": None,
                }
            },
            "technologies": {
                "22": [
                    {
                        "name": "OpenSSH 6.6.1p1",
                        "category": "remote-access",
                        "detected_from": "banner",
                    }
                ],
                "80": [
                    {
                        "name": "Apache 2.4.7",
                        "category": "web-server",
                        "detected_from": "banner",
                    }
                ],
            },
            "workers": 100,
            "timeout": 1.0,
            "duration_seconds": 0.5,
        }
    }

    report_file = tmp_path / "report.json"

    report_file.write_text(
        json.dumps(report),
        encoding="utf-8",
    )

    data = json.loads(
        report_file.read_text(encoding="utf-8")
    )

    assert "atlas_scan" in data
    assert data["atlas_scan"]["target"] == "scanme.nmap.org"
    assert data["atlas_scan"]["open_ports"] == [22, 80]
    assert data["atlas_scan"]["banners"]["22"].startswith("SSH")
    assert data["atlas_scan"]["services"]["22"]["service"] == "ssh"
    assert data["atlas_scan"]["services"]["80"]["service"] == "http"
    assert data["atlas_scan"]["http"]["80"]["status_code"] == 200
    assert data["atlas_scan"]["technologies"]["22"][0]["name"] == "OpenSSH 6.6.1p1"


def test_banner_grabber_returns_string_or_none():
    result = grab_banner(
        "scanme.nmap.org",
        22,
    )

    assert result is None or isinstance(result, str)


def test_ssh_service_identification():
    result = identify_service(
        22,
        "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13",
    )

    assert result["service"] == "ssh"
    assert result["version"] == "6.6.1p1"


def test_http_service_identification():
    result = identify_service(
        80,
        "HTTP/1.1 200 OK\r\n"
        "Server: Apache/2.4.7 (Ubuntu)",
    )

    assert result["service"] == "http"
    assert result["version"] == "2.4.7"


def test_port_based_service_identification():
    result = identify_service(21, None)

    assert result["service"] == "ftp"
    assert result["version"] == "unknown"


def test_http_inspection_returns_expected_structure():
    result = inspect_http(
        "scanme.nmap.org",
        80,
    )

    expected_keys = {
        "status_code",
        "server",
        "content_type",
        "content_length",
        "allow",
    }

    assert set(result.keys()) == expected_keys
    assert result["status_code"] is None or isinstance(
        result["status_code"],
        int,
    )


def test_ssh_technology_fingerprint():
    result = fingerprint_technology(
        "ssh",
        "6.6.1p1",
        "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13",
    )

    assert result
    assert result[0]["name"] == "OpenSSH 6.6.1p1"
    assert result[0]["category"] == "remote-access"


def test_http_technology_fingerprint():
    result = fingerprint_technology(
        "http",
        "2.4.7",
        "HTTP/1.1 200 OK",
        {
            "status_code": 200,
            "server": "Apache/2.4.7 (Ubuntu)",
            "content_type": "text/html",
            "content_length": None,
            "allow": None,
        },
    )

    assert result
    assert any(
        tech["name"] == "Apache 2.4.7"
        for tech in result
    )


def test_unknown_technology_returns_empty_list():
    result = fingerprint_technology(
        "unknown",
        None,
        None,
        None,
    )

    assert result == []
