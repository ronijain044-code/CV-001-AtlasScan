import pytest

from src.atlasscan.utils import parse_ports


def test_parse_single_port():
    assert parse_ports("22") == [22]


def test_parse_multiple_ports():
    assert parse_ports("22,80,443") == [22, 80, 443]


def test_parse_port_range():
    assert parse_ports("20-25") == [
        20,
        21,
        22,
        23,
        24,
        25,
    ]


def test_parse_mixed_ports_and_ranges():
    assert parse_ports("20-25,80,443") == [
        20,
        21,
        22,
        23,
        24,
        25,
        80,
        443,
    ]


def test_parse_removes_duplicates():
    assert parse_ports("22,22,80,80") == [22, 80]


def test_parse_strips_whitespace():
    assert parse_ports(" 22, 80, 443 ") == [
        22,
        80,
        443,
    ]


@pytest.mark.parametrize(
    "value",
    [
        "",
        " ",
        "abc",
        "22,abc",
        "80-",
        "-80",
        "80-abc",
        "abc-100",
        "80-70",
        "0",
        "65536",
        "1-65536",
    ],
)
def test_invalid_port_specifications_raise_value_error(value):
    with pytest.raises(ValueError):
        parse_ports(value)


def test_port_boundaries_are_valid():
    assert parse_ports("1") == [1]
    assert parse_ports("65535") == [65535]


def test_full_port_range_is_supported():
    result = parse_ports("1-65535")

    assert len(result) == 65535
    assert result[0] == 1
    assert result[-1] == 65535
