from pathlib import Path

from src.atlasscan.models import ScanResult
from src.atlasscan.report import generate_html_report


def make_minimal_result():
    return ScanResult.create(
        target="example.com",
        ports_scanned=0,
        workers=1,
        timeout=1.0,
        profile="quick",
    )


def test_minimal_result_to_dict_is_serializable():
    result = make_minimal_result()

    data = result.to_dict()

    assert isinstance(data, dict)
    assert data["target"] == "example.com"


def test_minimal_result_to_report_contains_atlas_scan():
    result = make_minimal_result()

    report = result.to_report()

    assert "atlas_scan" in report
    assert report["atlas_scan"]["target"] == "example.com"


def test_html_report_handles_minimal_result(tmp_path):
    result = make_minimal_result()

    output = tmp_path / "minimal.html"

    generate_html_report(
        filename=str(output),
        result=result,
    )

    assert output.exists()
    assert output.stat().st_size > 0


def test_html_report_creates_nested_parent_directories(tmp_path):
    result = make_minimal_result()

    output = (
        tmp_path
        / "reports"
        / "2026"
        / "scan"
        / "report.html"
    )

    generate_html_report(
        filename=str(output),
        result=result,
    )

    assert output.exists()
    assert output.is_file()


def test_html_report_handles_empty_sections(tmp_path):
    result = make_minimal_result()

    result.open_ports = []
    result.services = {}
    result.banners = {}
    result.http = {}
    result.technologies = {}
    result.dns = {
        "a": [],
        "aaaa": [],
        "ptr": {},
    }
    result.subdomains = []
    result.web = {}
    result.security = {}
    result.vulnerabilities = {}
    result.web_paths = {}
    result.robots = {}

    output = tmp_path / "empty.html"

    generate_html_report(
        filename=str(output),
        result=result,
    )

    content = output.read_text(encoding="utf-8")

    assert "<html" in content.lower()
    assert "example.com" in content


def test_html_report_escapes_special_target_characters(tmp_path):
    result = make_minimal_result()

    result.target = '<test>&"'

    output = tmp_path / "escaped.html"

    generate_html_report(
        filename=str(output),
        result=result,
    )

    content = output.read_text(encoding="utf-8")

    assert "&lt;test&gt;" in content
    assert "&amp;" in content
    assert "&quot;" in content


def test_html_report_escapes_finding_values(tmp_path):
    result = make_minimal_result()

    result.vulnerabilities = {
        80: [
            {
                "cve": "<CVE>",
                "severity": "high",
                "product": "<Apache>",
                "evidence": "<script>alert(1)</script>",
            }
        ]
    }

    output = tmp_path / "finding.html"

    generate_html_report(
        filename=str(output),
        result=result,
    )

    content = output.read_text(encoding="utf-8")

    assert "&lt;CVE&gt;" in content
    assert "&lt;Apache&gt;" in content
    assert "&lt;script&gt;" in content
    assert "<script>alert(1)</script>" not in content


def test_html_report_contains_no_python_object_repr(tmp_path):
    result = make_minimal_result()

    output = tmp_path / "repr.html"

    generate_html_report(
        filename=str(output),
        result=result,
    )

    content = output.read_text(encoding="utf-8")

    assert "object at 0x" not in content


def test_html_report_is_valid_text_utf8(tmp_path):
    result = make_minimal_result()

    result.target = "café.example"

    output = tmp_path / "unicode.html"

    generate_html_report(
        filename=str(output),
        result=result,
    )

    content = output.read_text(encoding="utf-8")

    assert "café.example" in content


def test_report_output_path_accepts_path_object(tmp_path):
    result = make_minimal_result()

    output = Path(tmp_path) / "path-object.html"

    generate_html_report(
        filename=output,
        result=result,
    )

    assert output.exists()
