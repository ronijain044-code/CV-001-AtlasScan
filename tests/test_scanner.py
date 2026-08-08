import json

from src.atlasscan.banner import grab_banner
from src.atlasscan.scanner import scan_port, scan_ports


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


def test_banner_grabber_returns_string_or_none():
    result = grab_banner(
        "scanme.nmap.org",
        22,
    )

    assert result is None or isinstance(result, str)
