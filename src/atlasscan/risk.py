from __future__ import annotations

from typing import Any


SEVERITY_DEDUCTIONS = {
    "critical": 25,
    "high": 10,
    "medium": 5,
    "low": 2,
}


def _severity_counts() -> dict[str, int]:
    return {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    }


def _extract_observations(
    data: dict[int, Any] | None,
    key: str,
) -> list[dict[str, Any]]:
    """
    Extract observations/findings from a port-keyed result structure.

    Supports both formats:

    Security:
        {
            80: {
                "observations": [...]
            }
        }

    Vulnerabilities:
        {
            80: [
                {...},
                {...}
            ]
        }

    Also supports the wrapped format:

        {
            80: {
                "findings": [...]
            }
        }
    """

    if not data:
        return []

    observations: list[dict[str, Any]] = []

    for details in data.values():

        # -----------------------------------------------------
        # Format 1:
        # port -> list of findings
        # Used by ScanResult.vulnerabilities
        # -----------------------------------------------------
        if isinstance(details, list):
            for item in details:
                if isinstance(item, dict):
                    observations.append(item)

            continue

        # -----------------------------------------------------
        # Format 2:
        # port -> {"observations": [...]}
        # or
        # port -> {"findings": [...]}
        # -----------------------------------------------------
        if isinstance(details, dict):

            items = details.get(key, [])

            if not isinstance(items, list):
                continue

            for item in items:
                if isinstance(item, dict):
                    observations.append(item)

    return observations


def _count_severities(
    observations: list[dict[str, Any]],
) -> dict[str, int]:
    counts = _severity_counts()

    for observation in observations:
        severity = str(
            observation.get("severity", "")
        ).strip().lower()

        if severity in counts:
            counts[severity] += 1

    return counts


def _calculate_deduction(
    counts: dict[str, int],
) -> int:
    deduction = 0

    for severity, count in counts.items():
        deduction += (
            SEVERITY_DEDUCTIONS[severity] * count
        )

    return deduction


def _grade_from_score(score: int) -> str:
    if score >= 90:
        return "A"

    if score >= 75:
        return "B"

    if score >= 60:
        return "C"

    if score >= 40:
        return "D"

    return "F"


def _risk_level_from_grade(grade: str) -> str:
    if grade == "A":
        return "low"

    if grade == "B":
        return "moderate"

    if grade == "C":
        return "elevated"

    if grade == "D":
        return "high"

    return "critical"


def calculate_unified_risk(
    security: dict[int, dict[str, Any]] | None = None,
    vulnerabilities: dict[int, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """
    Calculate a unified security risk score.

    The score starts at 100 and deductions are applied for
    security-header observations and vulnerability findings.

    Severity deductions:

        critical = 25
        high     = 10
        medium   = 5
        low      = 2

    Returns a normalized result containing:

        score
        grade
        risk_level
        observation_count
        security_observation_count
        vulnerability_count
        breakdown
        deductions
    """

    security = security or {}
    vulnerabilities = vulnerabilities or {}

    security_observations = _extract_observations(
        security,
        "observations",
    )

    vulnerability_findings = _extract_observations(
        vulnerabilities,
        "findings",
    )

    security_counts = _count_severities(
        security_observations
    )

    vulnerability_counts = _count_severities(
        vulnerability_findings
    )

    security_deduction = _calculate_deduction(
        security_counts
    )

    vulnerability_deduction = _calculate_deduction(
        vulnerability_counts
    )

    total_deduction = (
        security_deduction
        + vulnerability_deduction
    )

    score = max(
        0,
        min(
            100,
            100 - total_deduction,
        ),
    )

    grade = _grade_from_score(score)

    risk_level = _risk_level_from_grade(grade)

    security_count = len(
        security_observations
    )

    vulnerability_count = len(
        vulnerability_findings
    )

    observation_count = (
        security_count
        + vulnerability_count
    )

    return {
        "score": score,
        "grade": grade,
        "risk_level": risk_level,

        "observation_count": observation_count,

        "security_observation_count": (
            security_count
        ),

        "vulnerability_count": (
            vulnerability_count
        ),

        "security_critical_count": (
            security_counts["critical"]
        ),

        "security_high_count": (
            security_counts["high"]
        ),

        "security_medium_count": (
            security_counts["medium"]
        ),

        "security_low_count": (
            security_counts["low"]
        ),

        "vulnerability_critical_count": (
            vulnerability_counts["critical"]
        ),

        "vulnerability_high_count": (
            vulnerability_counts["high"]
        ),

        "vulnerability_medium_count": (
            vulnerability_counts["medium"]
        ),

        "vulnerability_low_count": (
            vulnerability_counts["low"]
        ),

        "breakdown": {
            "security": security_counts,
            "vulnerabilities": vulnerability_counts,
        },

        "deductions": {
            "security": security_deduction,
            "vulnerabilities": vulnerability_deduction,
            "total": total_deduction,
        },
    }
