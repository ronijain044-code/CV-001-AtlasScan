from pathlib import Path

from src.atlasscan.models import ScanResult
from src.atlasscan.report import generate_html_report


def make_test_result() -> ScanResult:
    result = ScanResult.create(
        target="example.com",
        ports_scanned=3,
        workers=10,
        timeout=1.0,
        profile="quick",
    )

    result.open_ports = [22, 80]

    result.services = {
        22: {
            "service": "ssh",
            "version": "OpenSSH 9.0",
        },
        80: {
            "service": "http",
            "version": "Apache 2.4.7",
        },
    }

    result.banners = {
        22: "SSH-2.0-OpenSSH_9.0",
        80: "Apache/2.4.7",
    }

    result.http = {
        80: {
            "status": 200,
            "server": "Apache/2.4.7",
            "content_type": "text/html",
        },
    }

    result.technologies = {
        80: [
            {
                "name": "Apache",
                "category": "web-server",
            }
        ],
    }

    result.dns = {
        "a": ["93.184.216.34"],
        "aaaa": [],
        "ptr": {},
    }

    result.subdomains = []

    result.web = {
        80: {
            "status": 200,
            "title": "Example Domain",
        },
    }

    result.security = {
        80: {
            "observations": [
                {
                    "severity": "high",
                    "finding": "Missing CSP",
                    "evidence": "Header not observed",
                }
            ]
        }
    }

    result.vulnerabilities = {
        80: [
            {
                "cve": "CVE-TEST-0001",
                "severity": "high",
                "product": "Apache HTTP Server",
                "evidence": "Test vulnerability",
            }
        ]
    }

    result.web_paths = {
        80: [
            {
                "path": "/",
                "status": 200,
                "content_type": "text/html",
            }
        ]
    }

    result.robots = {
        80: {
            "status": 404,
            "exists": False,
        }
    }

    result.unified_risk = {
        "score": 72,
        "grade": "B",
        "risk_level": "medium",
        "breakdown": {
            "security": {
                "score": 70,
            },
            "vulnerabilities": {
                "score": 75,
            },
        },
    }

    result.duration_seconds = 1.25

    return result


def test_scan_result_to_dict_contains_all_major_sections():
    result = make_test_result()

    data = result.to_dict()

    assert data["target"] == "example.com"
    assert data["open_ports"] == [22, 80]

    assert "services" in data
    assert "banners" in data
    assert "http" in data
    assert "technologies" in data
    assert "dns" in data
    assert "subdomains" in data
    assert "web" in data
    assert "security" in data
    assert "web_paths" in data
    assert "robots" in data
    assert "vulnerabilities" in data

    assert "unified_risk" in data
    assert data["unified_risk"]["score"] == 72
    assert data["unified_risk"]["grade"] == "B"
    assert data["unified_risk"]["risk_level"] == "medium"


def test_scan_result_to_report_wraps_result():
    result = make_test_result()

    report = result.to_report()

    assert "atlas_scan" in report
    assert report["atlas_scan"]["target"] == "example.com"
    assert report["atlas_scan"]["unified_risk"]["score"] == 72


def test_html_report_is_created(tmp_path):
    result = make_test_result()

    output = tmp_path / "report.html"

    generate_html_report(
        filename=str(output),
        result=result,
    )

    assert output.exists()
    assert output.is_file()
    assert output.stat().st_size > 0


def test_html_report_contains_target_and_risk(tmp_path):
    result = make_test_result()

    output = tmp_path / "report.html"

    generate_html_report(
        filename=str(output),
        result=result,
    )

    content = output.read_text(encoding="utf-8")

    assert "example.com" in content
    assert "Unified Risk Score" in content
    assert "72 / 100" in content
    assert "B" in content
    assert "MEDIUM" in content


def test_html_report_contains_scan_findings(tmp_path):
    result = make_test_result()

    output = tmp_path / "report.html"

    generate_html_report(
        filename=str(output),
        result=result,
    )

    content = output.read_text(encoding="utf-8")

    assert "OpenSSH 9.0" in content
    assert "Apache/2.4.7" in content
    assert "CVE-TEST-0001" in content


def test_html_report_escapes_html_values(tmp_path):
    result = make_test_result()

    result.target = "<script>alert('xss')</script>"

    output = tmp_path / "report.html"

    generate_html_report(
        filename=str(output),
        result=result,
    )

    content = output.read_text(encoding="utf-8")

    assert "<script>alert('xss')</script>" not in content
    assert "&lt;script&gt;" in content
