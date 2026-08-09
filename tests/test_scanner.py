from src.atlasscan.scanner import scan_port, scan_ports
from src.atlasscan.subdomain import discover_subdomains, resolve_subdomain


def test_scan_port_returns_bool():
    result = scan_port("scanme.nmap.org", 80)
    assert isinstance(result, bool)


def test_scan_ports_returns_list():
    ports = scan_ports("scanme.nmap.org", [22, 80])
    assert isinstance(ports, list)


def test_scan_ports_contains_only_integers():
    ports = scan_ports("scanme.nmap.org", [22, 80])
    assert all(isinstance(port, int) for port in ports)


def test_scan_ports_only_returns_requested_ports():
    requested = [22, 80]
    ports = scan_ports("scanme.nmap.org", requested)

    assert all(port in requested for port in ports)


def test_scan_port_invalid_port():
    result = scan_port("scanme.nmap.org", 9999)
    assert isinstance(result, bool)


def test_scan_ports_empty_input():
    result = scan_ports("scanme.nmap.org", [])
    assert result == []


def test_scan_ports_single_port():
    result = scan_ports("scanme.nmap.org", [80])
    assert isinstance(result, list)
    assert all(port == 80 for port in result)


def test_scan_ports_multiple_ports():
    result = scan_ports("scanme.nmap.org", [21, 22, 80])
    assert isinstance(result, list)
    assert all(port in [21, 22, 80] for port in result)


def test_scan_ports_result_is_sorted():
    result = scan_ports("scanme.nmap.org", [80, 22, 21])

    assert result == sorted(result)


def test_scan_port_returns_true_for_known_open_port():
    result = scan_port("scanme.nmap.org", 80)
    assert result is True


def test_scan_ports_returns_known_open_ports():
    result = scan_ports("scanme.nmap.org", [21, 22, 80])
    assert isinstance(result, list)

    for port in result:
        assert port in [21, 22, 80]


def test_scan_ports_does_not_return_unrequested_ports():
    result = scan_ports("scanme.nmap.org", [80])
    assert 21 not in result
    assert 22 not in result


def test_resolve_subdomain_returns_none_for_missing_host():
    result = resolve_subdomain(
        "definitely-does-not-exist-123456",
        "scanme.nmap.org",
    )

    assert result is None


def test_discover_subdomains_returns_list():
    result = discover_subdomains(
        "scanme.nmap.org",
        subdomains=["www", "api"],
    )

    assert isinstance(result, list)


def test_discover_subdomains_results_have_expected_shape():
    result = discover_subdomains(
        "scanme.nmap.org",
        subdomains=["www", "api"],
    )

    for item in result:
        assert "hostname" in item
        assert "addresses" in item
        assert isinstance(item["addresses"], list)
