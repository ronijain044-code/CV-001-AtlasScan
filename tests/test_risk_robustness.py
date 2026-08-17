import pytest

from src.atlasscan.risk import (
    MAX_VULNERABILITY_DEDUCTION,
    SEVERITY_DEDUCTIONS,
    _calculate_deduction,
    _calculate_vulnerability_deduction,
    _extract_observations,
    _count_severities,
    _grade_from_score,
    _risk_level_from_grade,
    calculate_unified_risk,
)


def test_none_inputs_return_perfect_score():
    result = calculate_unified_risk(
        security=None,
        vulnerabilities=None,
    )

    assert result["score"] == 100
    assert result["grade"] == "A"
    assert result["risk_level"] == "low"


def test_empty_structures_are_safe():
    result = calculate_unified_risk(
        security={},
        vulnerabilities={},
    )

    assert result["observation_count"] == 0
    assert result["security_observation_count"] == 0
    assert result["vulnerability_count"] == 0


def test_invalid_items_are_ignored():
    result = calculate_unified_risk(
        security={
            80: [
                None,
                "invalid",
                123,
                {"severity": "high"},
            ]
        },
        vulnerabilities={
            80: [
                None,
                {"severity": "critical"},
            ]
        },
    )

    assert result["security_observation_count"] == 1
    assert result["vulnerability_count"] == 1


def test_invalid_container_shapes_are_ignored():
    result = calculate_unified_risk(
        security={
            80: "invalid",
            443: None,
            22: 123,
        },
        vulnerabilities={
            80: "invalid",
            443: None,
        },
    )

    assert result["observation_count"] == 0
    assert result["score"] == 100


def test_unknown_severities_do_not_affect_score():
    result = calculate_unified_risk(
        security={
            80: {
                "observations": [
                    {"severity": "unknown"},
                    {"severity": "info"},
                    {"severity": ""},
                    {},
                ]
            }
        },
        vulnerabilities={},
    )

    assert result["score"] == 100
    assert result["observation_count"] == 4
    assert result["security_critical_count"] == 0
    assert result["security_high_count"] == 0
    assert result["security_medium_count"] == 0
    assert result["security_low_count"] == 0


def test_severity_matching_is_case_insensitive():
    result = calculate_unified_risk(
        security={
            80: {
                "observations": [
                    {"severity": "CRITICAL"},
                    {"severity": "High"},
                    {"severity": "MEDIUM"},
                    {"severity": "Low"},
                ]
            }
        },
        vulnerabilities={},
    )

    assert result["security_critical_count"] == 1
    assert result["security_high_count"] == 1
    assert result["security_medium_count"] == 1
    assert result["security_low_count"] == 1
    assert result["score"] == 58


def test_severity_whitespace_is_normalized():
    result = calculate_unified_risk(
        security={
            80: {
                "observations": [
                    {"severity": "  high  "},
                    {"severity": "\tmedium\n"},
                ]
            }
        },
        vulnerabilities={},
    )

    assert result["score"] == 85


def test_vulnerability_deduction_is_capped():
    counts = {
        "critical": 10,
        "high": 10,
        "medium": 10,
        "low": 10,
    }

    raw = _calculate_deduction(counts)
    capped = _calculate_vulnerability_deduction(counts)

    assert raw > MAX_VULNERABILITY_DEDUCTION
    assert capped == MAX_VULNERABILITY_DEDUCTION


def test_security_deduction_is_not_capped():
    counts = {
        "critical": 10,
        "high": 10,
        "medium": 10,
        "low": 10,
    }

    deduction = _calculate_deduction(counts)

    expected = sum(
        SEVERITY_DEDUCTIONS[key] * value
        for key, value in counts.items()
    )

    assert deduction == expected
    assert deduction > MAX_VULNERABILITY_DEDUCTION


def test_grade_boundaries_exact():
    assert _grade_from_score(100) == "A"
    assert _grade_from_score(90) == "A"
    assert _grade_from_score(89) == "B"
    assert _grade_from_score(75) == "B"
    assert _grade_from_score(74) == "C"
    assert _grade_from_score(60) == "C"
    assert _grade_from_score(59) == "D"
    assert _grade_from_score(40) == "D"
    assert _grade_from_score(39) == "F"
    assert _grade_from_score(0) == "F"


def test_risk_level_boundaries():
    assert _risk_level_from_grade("A") == "low"
    assert _risk_level_from_grade("B") == "moderate"
    assert _risk_level_from_grade("C") == "elevated"
    assert _risk_level_from_grade("D") == "high"
    assert _risk_level_from_grade("F") == "critical"


def test_negative_score_is_clamped_to_zero():
    result = calculate_unified_risk(
        security={
            80: {
                "observations": [
                    {"severity": "critical"},
                ]
                * 10
            }
        },
        vulnerabilities={},
    )

    assert result["score"] == 0
    assert result["grade"] == "F"
    assert result["risk_level"] == "critical"


def test_vulnerability_cap_preserves_score_floor():
    result = calculate_unified_risk(
        security={},
        vulnerabilities={
            80: {
                "findings": [
                    {"severity": "critical"},
                ]
                * 20
            }
        },
    )

    assert result["score"] == 50
    assert result["grade"] == "D"
    assert result["risk_level"] == "high"


def test_extract_observations_supports_list_format():
    data = {
        80: [
            {"severity": "high"},
            {"severity": "low"},
        ]
    }

    result = _extract_observations(data, "findings")

    assert len(result) == 2


def test_extract_observations_supports_dict_format():
    data = {
        80: {
            "findings": [
                {"severity": "critical"},
            ]
        }
    }

    result = _extract_observations(data, "findings")

    assert len(result) == 1
    assert result[0]["severity"] == "critical"


def test_extract_observations_ignores_non_list_findings():
    data = {
        80: {
            "findings": {"severity": "high"},
        }
    }

    result = _extract_observations(data, "findings")

    assert result == []


def test_count_severities_ignores_unknown_values():
    observations = [
        {"severity": "critical"},
        {"severity": "high"},
        {"severity": "medium"},
        {"severity": "low"},
        {"severity": "info"},
        {},
    ]

    counts = _count_severities(observations)

    assert counts == {
        "critical": 1,
        "high": 1,
        "medium": 1,
        "low": 1,
    }


def test_result_is_deterministic():
    security = {
        80: {
            "observations": [
                {"severity": "high"},
                {"severity": "medium"},
            ]
        }
    }

    vulnerabilities = {
        443: {
            "findings": [
                {"severity": "critical"},
            ]
        }
    }

    first = calculate_unified_risk(security, vulnerabilities)
    second = calculate_unified_risk(security, vulnerabilities)

    assert first == second


def test_observation_count_includes_unknown_severity_items():
    result = calculate_unified_risk(
        security={
            80: {
                "observations": [
                    {"severity": "high"},
                    {"severity": "info"},
                ]
            }
        },
        vulnerabilities={},
    )

    assert result["observation_count"] == 2
    assert result["security_observation_count"] == 2
    assert result["security_high_count"] == 1
