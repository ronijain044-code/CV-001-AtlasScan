import pytest

from src.atlasscan import cli


def run_cli(monkeypatch, argv):
    monkeypatch.setattr("sys.argv", ["atlasscan", *argv])

    with pytest.raises(SystemExit) as exc_info:
        cli.main()

    return exc_info.value.code


def test_missing_target_exits_with_usage(monkeypatch):
    code = run_cli(monkeypatch, [])

    assert code == 2


def test_invalid_target_exits_cleanly(monkeypatch):
    code = run_cli(
        monkeypatch,
        ["not a valid target"],
    )

    assert code == 2


@pytest.mark.parametrize(
    "timeout",
    ["0", "-1", "-0.5"],
)
def test_invalid_timeout_exits_cleanly(monkeypatch, timeout):
    code = run_cli(
        monkeypatch,
        [
            "scanme.nmap.org",
            "--timeout",
            timeout,
        ],
    )

    assert code == 2


@pytest.mark.parametrize(
    "workers",
    ["0", "-1"],
)
def test_invalid_workers_exits_cleanly(monkeypatch, workers):
    code = run_cli(
        monkeypatch,
        [
            "scanme.nmap.org",
            "--workers",
            workers,
        ],
    )

    assert code == 2


def test_non_numeric_timeout_exits_cleanly(monkeypatch):
    code = run_cli(
        monkeypatch,
        [
            "scanme.nmap.org",
            "--timeout",
            "abc",
        ],
    )

    assert code == 2


def test_non_numeric_workers_exits_cleanly(monkeypatch):
    code = run_cli(
        monkeypatch,
        [
            "scanme.nmap.org",
            "--workers",
            "abc",
        ],
    )

    assert code == 2


def test_invalid_profile_exits_cleanly(monkeypatch):
    code = run_cli(
        monkeypatch,
        [
            "scanme.nmap.org",
            "--profile",
            "invalid",
        ],
    )

    assert code == 2


def test_invalid_port_zero_exits_cleanly(monkeypatch):
    code = run_cli(
        monkeypatch,
        [
            "scanme.nmap.org",
            "--ports",
            "0",
        ],
    )

    assert code == 2


def test_invalid_port_too_large_exits_cleanly(monkeypatch):
    code = run_cli(
        monkeypatch,
        [
            "scanme.nmap.org",
            "--ports",
            "65536",
        ],
    )

    assert code == 2


def test_invalid_reversed_port_range_exits_cleanly(monkeypatch):
    code = run_cli(
        monkeypatch,
        [
            "scanme.nmap.org",
            "--ports",
            "100-20",
        ],
    )

    assert code == 2


def test_invalid_port_range_multiple_separators_exits_cleanly(
    monkeypatch,
):
    code = run_cli(
        monkeypatch,
        [
            "scanme.nmap.org",
            "--ports",
            "20-30-40",
        ],
    )

    assert code == 2


def test_invalid_empty_port_value_exits_cleanly(monkeypatch):
    code = run_cli(
        monkeypatch,
        [
            "scanme.nmap.org",
            "--ports",
            "22,,80",
        ],
    )

    assert code == 2


def test_help_exits_successfully(monkeypatch):
    code = run_cli(
        monkeypatch,
        ["--help"],
    )

    assert code == 0


def test_versionless_cli_requires_target(monkeypatch):
    code = run_cli(
        monkeypatch,
        ["--profile", "quick"],
    )

    assert code == 2


def test_json_requires_filename(monkeypatch):
    code = run_cli(
        monkeypatch,
        [
            "scanme.nmap.org",
            "--json",
        ],
    )

    assert code == 2


def test_html_requires_filename(monkeypatch):
    code = run_cli(
        monkeypatch,
        [
            "scanme.nmap.org",
            "--html",
        ],
    )

    assert code == 2
