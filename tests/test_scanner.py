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
