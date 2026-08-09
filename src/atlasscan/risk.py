from __future__ import annotations

from typing import Any


# ---------------------------------------------------------
# Severity configuration
# ---------------------------------------------------------

SEVERITY_DEDUCTIONS = {
    "critical": 25,
    "high": 10,
    "medium": 5,
    "low": 2,
}

# Vulnerabilities are capped so multiple CVEs do not make
# the score meaningless by themselves.
MAX_VULNERABILITY_DEDUCTION = 50


# ---------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------

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

    Supports:

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

    Also supports:

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

        # -------------------------------------------------
        # Format 1:
        # port -> list of findings
        # -------------------------------------------------

        if isinstance(details, list):
            for item in details:
                if isinstance(item, dict):
                    observations.append(item)

            continue

        # -------------------------------------------------
        # Format 2:
        # port -> {"observations": [...]}
        # or
        # port -> {"findings": [...]}
        # -------------------------------------------------

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


# ---------------------------------------------------------
# Deduction calculation
# ---------------------------------------------------------

def _calculate_deduction(
    counts: dict[str, int],
) -> int:
    """
    Calculate the raw deduction from severity counts.
    """

    deduction = 0

    for severity, count in counts.items():
        deduction += (
            SEVERITY_DEDUCTIONS[severity] * count
        )

    return deduction


def _calculate_vulnerability_deduction(
    counts: dict[str, int],
) -> int:
    """
    Calculate vulnerability deduction with a safety cap.

    The raw severity model remains:

        critical = 25
        high     = 10
        medium   = 5
        low      = 2

    but the total vulnerability contribution cannot exceed
    MAX_VULNERABILITY_DEDUCTION.
    """

    raw_deduction = _calculate_deduction(counts)

    return min(
        raw_deduction,
        MAX_VULNERABILITY_DEDUCTION,
    )


# ---------------------------------------------------------
# Grade calculation
# ---------------------------------------------------------

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


# ---------------------------------------------------------
# Risk level calculation
# ---------------------------------------------------------

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


# ---------------------------------------------------------
# Unified risk engine
# ---------------------------------------------------------

def calculate_unified_risk(
    security: dict[int, Any] | None = None,
    vulnerabilities: dict[int, Any] | None = None,
) -> dict[str, Any]:
    """
    Calculate a unified security risk score.

    The score starts at 100.

    Security observations use the full severity deduction:

        critical = 25
        high     = 10
        medium   = 5
        low      = 2

    Vulnerability findings use the same severity values,
    but the total vulnerability deduction is capped at 50.

    Returns:

        score
        grade
        risk_level

        observation_count
        security_observation_count
        vulnerability_count

        security_critical_count
        security_high_count
        security_medium_count
        security_low_count

        vulnerability_critical_count
        vulnerability_high_count
        vulnerability_medium_count
        vulnerability_low_count

        breakdown
        deductions
    """

    security = security or {}
    vulnerabilities = vulnerabilities or {}

    # -----------------------------------------------------
    # Extract observations
    # -----------------------------------------------------

    security_observations = _extract_observations(
        security,
        "observations",
    )

    vulnerability_findings = _extract_observations(
        vulnerabilities,
        "findings",
    )

    # -----------------------------------------------------
    # Count severities
    # -----------------------------------------------------

    security_counts = _count_severities(
        security_observations
    )

    vulnerability_counts = _count_severities(
        vulnerability_findings
    )

    # -----------------------------------------------------
    # Calculate deductions
    # -----------------------------------------------------

    security_deduction = _calculate_deduction(
        security_counts
    )

    raw_vulnerability_deduction = _calculate_deduction(
        vulnerability_counts
    )

    vulnerability_deduction = (
        _calculate_vulnerability_deduction(
            vulnerability_counts
        )
    )

    total_deduction = (
        security_deduction
        + vulnerability_deduction
    )

    # -----------------------------------------------------
    # Calculate final score
    # -----------------------------------------------------

    score = max(
        0,
        min(
            100,
            100 - total_deduction,
        ),
    )

    # -----------------------------------------------------
    # Grade + risk level
    # -----------------------------------------------------

    grade = _grade_from_score(score)

    risk_level = _risk_level_from_grade(grade)

    # -----------------------------------------------------
    # Counts
    # -----------------------------------------------------

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

    # -----------------------------------------------------
    # Result
    # -----------------------------------------------------

    return {
        # ---------------------------------------------
        # Overall result
        # ---------------------------------------------

        "score": score,

        "grade": grade,

        "risk_level": risk_level,

        # ---------------------------------------------
        # Overall counts
        # ---------------------------------------------

        "observation_count": observation_count,

        "security_observation_count": (
            security_count
        ),

        "vulnerability_count": (
            vulnerability_count
        ),

        # ---------------------------------------------
        # Security severity counts
        # ---------------------------------------------

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

        # ---------------------------------------------
        # Vulnerability severity counts
        # ---------------------------------------------

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

        # ---------------------------------------------
        # Severity breakdown
        # ---------------------------------------------

        "breakdown": {
            "security": {
                "critical": security_counts["critical"],
                "high": security_counts["high"],
                "medium": security_counts["medium"],
                "low": security_counts["low"],
            },

            "vulnerabilities": {
                "critical": vulnerability_counts["critical"],
                "high": vulnerability_counts["high"],
                "medium": vulnerability_counts["medium"],
                "low": vulnerability_counts["low"],
            },
        },

        # ---------------------------------------------
        # Deduction details
        # ---------------------------------------------

        "deductions": {
            "security": security_deduction,

            "vulnerabilities": vulnerability_deduction,

            "vulnerabilities_raw": (
                raw_vulnerability_deduction
            ),

            "vulnerability_cap": (
                MAX_VULNERABILITY_DEDUCTION
            ),

            "total": total_deduction,
        },
    }
