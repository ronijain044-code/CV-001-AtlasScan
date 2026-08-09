import pytest

from src.atlasscan import cli


def test_invalid_port_specification_exits_cleanly(monkeypatch):
    monkeypatch.setattr(
        "sys.argv",
        [
            "atlasscan",
            "scanme.nmap.org",
            "-p",
            "abc",
        ],
    )

    with pytest.raises(SystemExit) as exc_info:
        cli.main()

    assert exc_info.value.code == 2


def test_invalid_port_range_exits_cleanly(monkeypatch):
    monkeypatch.setattr(
        "sys.argv",
        [
            "atlasscan",
            "scanme.nmap.org",
            "-p",
            "80-",
        ],
    )

    with pytest.raises(SystemExit) as exc_info:
        cli.main()

    assert exc_info.value.code == 2
