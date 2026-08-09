from src.atlasscan.risk import calculate_unified_risk


def test_no_findings_returns_perfect_score():
    result = calculate_unified_risk(
        security={},
        vulnerabilities={},
    )

    assert result["score"] == 100
    assert result["grade"] == "A"
    assert result["risk_level"] == "low"


def test_security_headers_reduce_score():
    result = calculate_unified_risk(
        security={
            80: {
                "observations": [
                    {"severity": "high"},
                    {"severity": "medium"},
                    {"severity": "low"},
                ]
            }
        },
        vulnerabilities={},
    )

    assert result["score"] < 100
    assert result["grade"] != "A"
    assert result["breakdown"]["security"]["high"] == 1
    assert result["breakdown"]["security"]["medium"] == 1
    assert result["breakdown"]["security"]["low"] == 1


def test_critical_vulnerability_has_major_impact():
    result = calculate_unified_risk(
        security={},
        vulnerabilities={
            80: {
                "findings": [
                    {"severity": "critical"},
                ]
            }
        },
    )

    assert result["score"] < 100
    assert result["breakdown"]["vulnerabilities"]["critical"] == 1


def test_high_vulnerability_has_major_impact():
    result = calculate_unified_risk(
        security={},
        vulnerabilities={
            80: {
                "findings": [
                    {"severity": "high"},
                ]
            }
        },
    )

    assert result["score"] < 100
    assert result["breakdown"]["vulnerabilities"]["high"] == 1


def test_multiple_vulnerabilities_stack():
    result = calculate_unified_risk(
        security={},
        vulnerabilities={
            80: {
                "findings": [
                    {"severity": "critical"},
                    {"severity": "high"},
                    {"severity": "medium"},
                    {"severity": "low"},
                ]
            }
        },
    )

    assert result["score"] < 100
    assert result["observation_count"] == 4


def test_combines_security_and_vulnerability_findings():
    result = calculate_unified_risk(
        security={
            80: {
                "observations": [
                    {"severity": "high"},
                ]
            }
        },
        vulnerabilities={
            80: {
                "findings": [
                    {"severity": "critical"},
                ]
            }
        },
    )

    assert result["score"] < 100

    assert result["breakdown"]["security"]["high"] == 1
    assert result["breakdown"]["vulnerabilities"]["critical"] == 1


def test_score_never_goes_below_zero():
    result = calculate_unified_risk(
        security={
            80: {
                "observations": [
                    {"severity": "critical"},
                    {"severity": "critical"},
                    {"severity": "critical"},
                    {"severity": "critical"},
                    {"severity": "critical"},
                ]
            }
        },
        vulnerabilities={
            80: {
                "findings": [
                    {"severity": "critical"},
                    {"severity": "critical"},
                    {"severity": "critical"},
                    {"severity": "critical"},
                    {"severity": "critical"},
                ]
            }
        },
    )

    assert result["score"] >= 0
    assert result["score"] <= 100


def test_grade_boundaries():
    # Perfect score
    result = calculate_unified_risk(
        security={},
        vulnerabilities={},
    )

    assert result["score"] == 100
    assert result["grade"] == "A"

    # Two critical + two high findings:
    #
    # 100
    # -25 critical
    # -25 critical
    # -10 high
    # -10 high
    # = 30
    #
    # 30 should be an F.
    result = calculate_unified_risk(
        security={
            80: {
                "observations": [
                    {"severity": "critical"},
                    {"severity": "critical"},
                    {"severity": "high"},
                    {"severity": "high"},
                ]
            }
        },
        vulnerabilities={},
    )

    assert result["score"] == 30
    assert result["grade"] == "F"


def test_risk_level_matches_grade():
    result = calculate_unified_risk(
        security={},
        vulnerabilities={},
    )

    assert result["grade"] == "A"
    assert result["risk_level"] == "low"


def test_result_contains_breakdown():
    result = calculate_unified_risk(
        security={
            80: {
                "observations": [
                    {"severity": "high"},
                ]
            }
        },
        vulnerabilities={
            80: {
                "findings": [
                    {"severity": "medium"},
                ]
            }
        },
    )

    assert "breakdown" in result
    assert "security" in result["breakdown"]
    assert "vulnerabilities" in result["breakdown"]
    assert "high" in result["breakdown"]["security"]
    assert "medium" in result["breakdown"]["vulnerabilities"]
