import pytest

from src.atlasscan.utils import parse_ports, validate_target


# ---------------------------------------------------------
# Port parsing robustness
# ---------------------------------------------------------

@pytest.mark.parametrize(
    "value",
    [
        None,
        22,
        22.5,
        [],
        {},
    ],
)
def test_parse_ports_rejects_non_strings(value):
    with pytest.raises(ValueError):
        parse_ports(value)


@pytest.mark.parametrize(
    "value",
    [
        "22,,80",
        ",22",
        "22,",
        "22,,",
        "22-",
        "-22",
        "22-80-90",
        "1-2-3",
    ],
)
def test_parse_ports_rejects_malformed_ranges(value):
    with pytest.raises(ValueError):
        parse_ports(value)


def test_parse_ports_handles_duplicate_ranges():
    assert parse_ports("20-22,21-23") == [
        20,
        21,
        22,
        23,
    ]


def test_parse_ports_returns_sorted_results():
    assert parse_ports("443,22,80,20-21") == [
        20,
        21,
        22,
        80,
        443,
    ]


def test_parse_ports_accepts_whitespace_inside_ranges():
    assert parse_ports(" 20 - 22 , 80 ") == [
        20,
        21,
        22,
        80,
    ]


# ---------------------------------------------------------
# Target validation robustness
# ---------------------------------------------------------

def test_validate_ipv4():
    assert validate_target("192.168.1.1") == "192.168.1.1"


def test_validate_ipv6():
    assert validate_target("2001:db8::1") == "2001:db8::1"


def test_validate_target_strips_outer_whitespace():
    assert validate_target("  example.com  ") == "example.com"


def test_validate_hostname():
    assert validate_target("scanme.nmap.org") == "scanme.nmap.org"


def test_validate_hostname_allows_trailing_dot():
    assert validate_target("example.com.") == "example.com."


@pytest.mark.parametrize(
    "value",
    [
        None,
        123,
        1.5,
        [],
        {},
    ],
)
def test_validate_target_rejects_non_strings(value):
    with pytest.raises(ValueError):
        validate_target(value)


@pytest.mark.parametrize(
    "value",
    [
        "",
        " ",
        "\t",
        "\n",
    ],
)
def test_validate_target_rejects_empty_values(value):
    with pytest.raises(ValueError):
        validate_target(value)


@pytest.mark.parametrize(
    "value",
    [
        "hello world",
        "example_com",
        "-example.com",
        "example-.com",
        ".example.com",
        "example..com",
        "example.-com",
        "example-.com",
        "http://example.com",
        "https://example.com",
        "example.com/path",
        "example.com:80",
    ],
)
def test_validate_target_rejects_invalid_hostnames(value):
    with pytest.raises(ValueError):
        validate_target(value)


def test_validate_hostname_label_boundary():
    label = "a" * 63
    target = f"{label}.example.com"

    assert validate_target(target) == target


def test_validate_hostname_rejects_label_over_63_characters():
    label = "a" * 64
    target = f"{label}.example.com"

    with pytest.raises(ValueError):
        validate_target(target)


def test_validate_hostname_rejects_hostname_over_253_characters():
    target = ".".join(["a" * 63] * 4) + ".com"

    assert len(target) > 253

    with pytest.raises(ValueError):
        validate_target(target)


@pytest.mark.parametrize(
    "value",
    [
        "0.0.0.0",
        "255.255.255.255",
        "127.0.0.1",
        "::1",
        "fe80::1",
        "2001:db8::abcd",
    ],
)
def test_validate_accepts_valid_ip_addresses(value):
    assert validate_target(value) == value


@pytest.mark.parametrize(
    "value",
    [
        "999.999.999.999",
        "256.1.1.1",
        "192.168.1",
        "192.168.1.999",
        "2001:::1",
        "gggg::1",
    ],
)
def test_validate_rejects_invalid_ip_addresses(value):
    with pytest.raises(ValueError):
        validate_target(value)
