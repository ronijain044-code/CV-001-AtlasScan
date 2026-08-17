import pytest

from src.atlasscan.utils import validate_target


def test_valid_hostname():
    assert validate_target("scanme.nmap.org") == "scanme.nmap.org"


def test_valid_ipv4():
    assert validate_target("192.168.1.1") == "192.168.1.1"


def test_valid_ipv6():
    assert validate_target("2001:db8::1") == "2001:db8::1"


def test_target_strips_whitespace():
    assert validate_target("  scanme.nmap.org  ") == "scanme.nmap.org"


@pytest.mark.parametrize(
    "target",
    [
        "",
        " ",
        "not a valid target",
        "hello world",
        "-invalid.com",
        "invalid-.com",
    ],
)
def test_invalid_targets_raise_value_error(target):
    with pytest.raises(ValueError):
        validate_target(target)


def test_non_string_target_raises_value_error():
    with pytest.raises(ValueError):
        validate_target(None)


def test_hostname_too_long_raises_value_error():
    target = "a" * 254

    with pytest.raises(ValueError):
        validate_target(target)
