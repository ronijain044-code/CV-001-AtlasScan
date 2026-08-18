import pytest

from src.atlasscan.config import PROFILES, get_profile


def test_profiles_are_non_empty():
    assert PROFILES
    assert all(PROFILES.values())


def test_profile_names_match_keys():
    for name, profile in PROFILES.items():
        assert profile.name == name


@pytest.mark.parametrize("name", ["quick", "standard", "thorough"])
def test_profile_lookup_accepts_whitespace(name):
    profile = get_profile(f"  {name}  ")
    assert profile.name == name


@pytest.mark.parametrize(
    "name",
    ["QUICK", "Quick", "qUiCk", "STANDARD", "Standard", "THOROUGH"],
)
def test_profile_lookup_is_case_insensitive(name):
    assert get_profile(name).name == name.strip().lower()


def test_unknown_profile_error_is_useful():
    with pytest.raises(ValueError) as exc:
        get_profile("does-not-exist")

    message = str(exc.value)

    assert "Unknown profile" in message
    assert "quick" in message
    assert "standard" in message
    assert "thorough" in message


@pytest.mark.parametrize(
    "value",
    ["", " ", "invalid", "fast", "full", "None"],
)
def test_invalid_profiles_raise_value_error(value):
    with pytest.raises(ValueError):
        get_profile(value)


def test_profiles_have_valid_ports():
    for profile in PROFILES.values():
        assert isinstance(profile.ports, str)
        assert profile.ports.strip()


def test_profiles_have_positive_timeout():
    for profile in PROFILES.values():
        assert profile.timeout > 0


def test_profiles_have_positive_workers():
    for profile in PROFILES.values():
        assert profile.workers > 0


def test_profiles_have_boolean_feature_flags():
    flags = (
        "dns",
        "subdomains",
        "banners",
        "http",
        "technologies",
        "vulnerabilities",
        "web",
        "security",
        "robots",
        "web_paths",
    )

    for profile in PROFILES.values():
        for flag in flags:
            assert isinstance(getattr(profile, flag), bool)
