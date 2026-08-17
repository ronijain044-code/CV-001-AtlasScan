from types import SimpleNamespace

from src.atlasscan import cli


def test_cli_main_runs_full_pipeline(monkeypatch, tmp_path):
    calls = []

    monkeypatch.setattr(
        "sys.argv",
        [
            "atlasscan",
            "example.com",
            "--ports",
            "22,80",
            "--timeout",
            "0.5",
            "--workers",
            "5",
        ],
    )

    monkeypatch.setattr(
        cli,
        "banner",
        lambda: calls.append("banner"),
    )

    monkeypatch.setattr(
        cli,
        "collect_dns_details",
        lambda target: calls.append(("dns", target)) or {
            "a": ["93.184.216.34"],
            "aaaa": [],
            "ptr": {},
        },
    )

    monkeypatch.setattr(
        cli,
        "collect_subdomains",
        lambda target: calls.append(("subdomains", target)) or [],
    )

    monkeypatch.setattr(
        cli,
        "scan_with_progress",
        lambda target, ports, timeout, workers:
            calls.append(
                ("scan", target, ports, timeout, workers)
            )
            or [80],
    )

    monkeypatch.setattr(
        cli,
        "collect_banners",
        lambda target, ports:
            calls.append(("banners", target, ports))
            or {
                80: "HTTP/1.1 200 OK\r\nServer: Apache/2.4.7"
            },
    )

    monkeypatch.setattr(
        cli,
        "build_service_results",
        lambda ports, banners:
            calls.append(("services", ports, banners))
            or {
                80: {
                    "service": "http",
                    "version": "2.4.7",
                }
            },
    )

    monkeypatch.setattr(
        cli,
        "collect_http_details",
        lambda target, ports, banners:
            calls.append(("http", target, ports))
            or {
                80: {
                    "status_code": 200,
                    "server": "Apache/2.4.7",
                    "content_type": "text/html",
                }
            },
    )

    monkeypatch.setattr(
        cli,
        "build_technology_results",
        lambda ports, banners, services, http:
            calls.append(("technology", ports))
            or {
                80: [
                    {
                        "name": "Apache 2.4.7",
                        "category": "web-server",
                    }
                ]
            },
    )

    monkeypatch.setattr(
        cli,
        "collect_vulnerability_details",
        lambda ports, services, banners, technologies:
            calls.append(("vulnerabilities", ports))
            or {},
    )

    monkeypatch.setattr(
        cli,
        "collect_web_details",
        lambda target, ports, timeout:
            calls.append(("web", target, ports, timeout))
            or {},
    )

    monkeypatch.setattr(
        cli,
        "collect_security_details",
        lambda web:
            calls.append(("security", web))
            or {},
    )

    monkeypatch.setattr(
        cli,
        "collect_robots_details",
        lambda target, ports, timeout:
            calls.append(("robots", target, ports, timeout))
            or {},
    )

    monkeypatch.setattr(
        cli,
        "collect_web_paths",
        lambda target, ports, timeout:
            calls.append(("web_paths", target, ports, timeout))
            or {},
    )

    monkeypatch.setattr(
        cli,
        "calculate_unified_risk",
        lambda security, vulnerabilities:
            calls.append(("risk", security, vulnerabilities))
            or {
                "score": 100,
                "grade": "A",
                "risk_level": "LOW",
            },
    )

    monkeypatch.setattr(
        cli,
        "display_dns_results",
        lambda data: None,
    )

    monkeypatch.setattr(
        cli,
        "display_subdomain_results",
        lambda data: None,
    )

    monkeypatch.setattr(
        cli,
        "display_web_results",
        lambda data: None,
    )

    monkeypatch.setattr(
        cli,
        "display_security_headers",
        lambda data: None,
    )

    monkeypatch.setattr(
        cli,
        "display_security_findings",
        lambda data: None,
    )

    monkeypatch.setattr(
        cli,
        "display_vulnerability_results",
        lambda data: None,
    )

    monkeypatch.setattr(
        cli,
        "display_robots_results",
        lambda data: None,
    )

    monkeypatch.setattr(
        cli,
        "display_web_path_results",
        lambda data: None,
    )

    cli.main()

    names = [
        item if isinstance(item, str) else item[0]
        for item in calls
    ]

    assert "banner" in names
    assert "dns" in names
    assert "subdomains" in names
    assert "scan" in names
    assert "banners" in names
    assert "services" in names
    assert "http" in names
    assert "technology" in names
    assert "vulnerabilities" in names
    assert "web" in names
    assert "security" in names
    assert "robots" in names
    assert "web_paths" in names
    assert "risk" in names

    scan_call = next(
        item for item in calls
        if isinstance(item, tuple) and item[0] == "scan"
    )

    assert scan_call[1] == "example.com"
    assert scan_call[2] == [22, 80]
    assert scan_call[3] == 0.5
    assert scan_call[4] == 5
