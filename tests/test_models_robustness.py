from src.atlasscan.models import ScanResult


def make_result():
    return ScanResult.create(
        target="example.com",
        ports_scanned=10,
        workers=20,
        timeout=1.0,
        profile="quick",
    )


def test_create_sets_required_fields():
    result = make_result()

    assert result.target == "example.com"
    assert result.ports_scanned == 10
    assert result.workers == 20
    assert result.timeout == 1.0
    assert result.profile == "quick"
    assert result.timestamp


def test_default_collections_are_empty():
    result = make_result()

    assert result.open_ports == []
    assert result.services == {}
    assert result.banners == {}
    assert result.http == {}
    assert result.technologies == {}
    assert result.dns == {}
    assert result.subdomains == []
    assert result.web == {}
    assert result.security == {}
    assert result.web_paths == {}
    assert result.robots == {}
    assert result.vulnerabilities == {}
    assert result.unified_risk == {}


def test_open_port_count():
    result = make_result()
    result.open_ports = [22, 80, 443]

    assert result.open_port_count == 3


def test_technology_count_handles_multiple_ports():
    result = make_result()
    result.technologies = {
        22: [{"name": "OpenSSH"}],
        80: [{"name": "Apache"}, {"name": "PHP"}],
        443: [],
    }

    assert result.technology_count == 3


def test_dns_record_count_handles_mixed_values():
    result = make_result()
    result.dns = {
        "a": ["1.2.3.4", "5.6.7.8"],
        "aaaa": [],
        "ptr": {
            "1.2.3.4": ["example.com"],
        },
    }

    assert result.dns_record_count == 3


def test_dns_record_count_handles_scalar_values():
    result = make_result()
    result.dns = {
        "a": "1.2.3.4",
        "status": 200,
        "empty": None,
    }

    assert result.dns_record_count == 2


def test_subdomain_count():
    result = make_result()
    result.subdomains = ["www.example.com", "api.example.com"]

    assert result.subdomain_count == 2


def test_web_count():
    result = make_result()
    result.web = {
        80: {"status": 200},
        443: {"status": 200},
    }

    assert result.web_count == 2


def test_web_path_count_ignores_invalid_values():
    result = make_result()
    result.web_paths = {
        80: [{"path": "/"}, {"path": "/login"}],
        443: "invalid",
        8080: None,
    }

    assert result.web_path_count == 2


def test_security_observation_count_ignores_invalid_observations():
    result = make_result()
    result.security = {
        80: {
            "observations": [
                {"severity": "high"},
                {"severity": "medium"},
            ]
        },
        443: {
            "observations": "invalid",
        },
    }

    assert result.security_observation_count == 2


def test_security_severity_counts():
    result = make_result()
    result.security = {
        80: {
            "observations": [
                {"severity": "high"},
                {"severity": "high"},
                {"severity": "medium"},
                {"severity": "low"},
            ]
        }
    }

    assert result.security_high_count == 2
    assert result.security_medium_count == 1
    assert result.security_low_count == 1


def test_security_risk_score_ignores_invalid_scores():
    result = make_result()
    result.security = {
        80: {"risk_score": 5},
        443: {"risk_score": "3"},
        8080: {"risk_score": "invalid"},
        9000: {"risk_score": None},
    }

    assert result.security_risk_score == 8


def test_security_grade_boundaries():
    result = make_result()

    expected = {
        0: "A",
        2: "A",
        3: "B",
        5: "B",
        6: "C",
        8: "C",
        9: "D",
        12: "D",
        13: "F",
    }

    for score, grade in expected.items():
        result.security = {80: {"risk_score": score}}
        assert result.security_grade == grade


def test_vulnerability_count_handles_invalid_containers():
    result = make_result()
    result.vulnerabilities = {
        80: [{"severity": "high"}],
        443: "invalid",
        8080: None,
    }

    assert result.vulnerability_count == 1


def test_vulnerability_severity_counts_are_case_insensitive():
    result = make_result()
    result.vulnerabilities = {
        80: [
            {"severity": "CRITICAL"},
            {"severity": "High"},
            {"severity": "MEDIUM"},
            {"severity": "low"},
        ]
    }

    assert result.vulnerability_critical_count == 1
    assert result.vulnerability_high_count == 1
    assert result.vulnerability_medium_count == 1
    assert result.vulnerability_low_count == 1


def test_to_dict_converts_port_keys_to_strings():
    result = make_result()

    result.services = {22: {"service": "ssh"}}
    result.banners = {22: "SSH"}
    result.http = {80: {"status": 200}}
    result.technologies = {80: [{"name": "Apache"}]}
    result.web = {80: {"title": "Example"}}
    result.security = {80: {"risk_score": 2}}
    result.web_paths = {80: [{"path": "/"}]}
    result.robots = {80: {"status": 200}}
    result.vulnerabilities = {80: [{"severity": "low"}]}

    data = result.to_dict()

    assert "22" in data["services"]
    assert "22" in data["banners"]
    assert "80" in data["http"]
    assert "80" in data["technologies"]
    assert "80" in data["web"]
    assert "80" in data["security"]
    assert "80" in data["web_paths"]
    assert "80" in data["robots"]
    assert "80" in data["vulnerabilities"]


def test_to_report_wraps_serialized_result():
    result = make_result()

    report = result.to_report()

    assert set(report) == {"atlas_scan"}
    assert report["atlas_scan"]["target"] == "example.com"


def test_repr_contains_class_and_target():
    result = make_result()

    representation = repr(result)

    assert "ScanResult" in representation
    assert "example.com" in representation
