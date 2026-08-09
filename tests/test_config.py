from src.atlasscan.config import PROFILES, get_profile


def test_all_profiles_exist():
    assert set(PROFILES) == {
        "quick",
        "standard",
        "thorough",
    }


def test_quick_profile():
    profile = get_profile("quick")

    assert profile.name == "quick"
    assert profile.ports == (
        "21,22,23,25,53,80,110,139,143,443,445,3306,3389,8080"
    )
    assert profile.timeout == 0.5
    assert profile.workers == 100

    assert profile.dns is True
    assert profile.subdomains is False
    assert profile.banners is True
    assert profile.http is True
    assert profile.technologies is True
    assert profile.vulnerabilities is True
    assert profile.web is False
    assert profile.security is True
    assert profile.robots is False
    assert profile.web_paths is False


def test_standard_profile():
    profile = get_profile("standard")

    assert profile.name == "standard"
    assert profile.ports == "1-1000"
    assert profile.timeout == 1.0
    assert profile.workers == 100

    assert profile.dns is True
    assert profile.subdomains is True
    assert profile.banners is True
    assert profile.http is True
    assert profile.technologies is True
    assert profile.vulnerabilities is True
    assert profile.web is True
    assert profile.security is True
    assert profile.robots is True
    assert profile.web_paths is True


def test_thorough_profile():
    profile = get_profile("thorough")

    assert profile.name == "thorough"
    assert profile.ports == "1-10000"
    assert profile.timeout == 1.5
    assert profile.workers == 100

    assert profile.dns is True
    assert profile.subdomains is True
    assert profile.banners is True
    assert profile.http is True
    assert profile.technologies is True
    assert profile.vulnerabilities is True
    assert profile.web is True
    assert profile.security is True
    assert profile.robots is True
    assert profile.web_paths is True


def test_profile_lookup_is_case_insensitive():
    assert get_profile("QUICK").name == "quick"
    assert get_profile("Standard").name == "standard"
    assert get_profile("THOROUGH").name == "thorough"


def test_unknown_profile_raises_value_error():
    try:
        get_profile("invalid")
    except ValueError as exc:
        assert "Unknown profile" in str(exc)
        assert "quick" in str(exc)
        assert "standard" in str(exc)
        assert "thorough" in str(exc)
    else:
        raise AssertionError("Expected ValueError")
