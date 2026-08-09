from __future__ import annotations

from typing import Any


SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "severity": "high",
        "description": (
            "Content-Security-Policy helps control which resources "
            "a browser is allowed to load."
        ),
        "weight": 25,
    },
    "Strict-Transport-Security": {
        "severity": "medium",
        "description": (
            "HSTS instructs browsers to use HTTPS for future requests."
        ),
        "weight": 15,
    },
    "X-Frame-Options": {
        "severity": "medium",
        "description": (
            "X-Frame-Options helps protect against clickjacking."
        ),
        "weight": 15,
    },
    "X-Content-Type-Options": {
        "severity": "low",
        "description": (
            "X-Content-Type-Options helps prevent MIME-type sniffing."
        ),
        "weight": 10,
    },
    "Referrer-Policy": {
        "severity": "low",
        "description": (
            "Referrer-Policy controls how much referrer information "
            "is sent with requests."
        ),
        "weight": 10,
    },
    "Permissions-Policy": {
        "severity": "low",
        "description": (
            "Permissions-Policy controls access to selected "
            "browser features."
        ),
        "weight": 10,
    },
}


SEVERITY_ORDER = {
    "high": 0,
    "medium": 1,
    "low": 2,
}


def _normalize_headers(
    headers: dict[str, Any] | None,
) -> dict[str, str]:
    """
    Normalize HTTP header names to lowercase.

    This allows callers to provide either:

        Content-Security-Policy

    or:

        content-security-policy
    """

    if not headers:
        return {}

    normalized: dict[str, str] = {}

    for key, value in headers.items():
        if value is None:
            continue

        normalized[str(key).lower()] = str(value).strip()

    return normalized


def _calculate_grade(score: int) -> str:
    """
    Convert a 0-100 security score into a letter grade.

    90-100 -> A
    80-89  -> B
    70-79  -> C
    60-69  -> D
    0-59   -> F
    """

    if score >= 90:
        return "A"

    if score >= 80:
        return "B"

    if score >= 70:
        return "C"

    if score >= 60:
        return "D"

    return "F"


def _severity_counts(
    observations: list[dict[str, Any]],
) -> dict[str, int]:
    """
    Count observations by severity.
    """

    counts = {
        "high": 0,
        "medium": 0,
        "low": 0,
    }

    for observation in observations:
        severity = str(
            observation.get("severity", "")
        ).lower()

        if severity in counts:
            counts[severity] += 1

    return counts


def _risk_score(
    observations: list[dict[str, Any]],
) -> int:
    """
    Calculate a 0-100 security score.

    The score starts at 100.

    Each missing security header subtracts its configured
    weight.

    The result is clamped between 0 and 100.
    """

    deduction = 0

    for observation in observations:
        header_name = observation.get(
            "header"
        )

        if header_name in SECURITY_HEADERS:
            deduction += SECURITY_HEADERS[
                header_name
            ]["weight"]
        else:
            severity = str(
                observation.get("severity", "")
            ).lower()

            if severity == "high":
                deduction += 25
            elif severity == "medium":
                deduction += 15
            elif severity == "low":
                deduction += 10

    return max(
        0,
        min(
            100,
            100 - deduction,
        ),
    )


def analyze_security_headers(
    headers: dict[str, Any] | None,
) -> dict[str, Any]:
    """
    Analyze common HTTP security headers.

    Returns:

        headers
        present_count
        missing_count
        total_count
        missing
        observations
        risk_score
        grade
        severity_counts
        high_count
        medium_count
        low_count
        observation_count
    """

    normalized = _normalize_headers(headers)

    analyzed_headers: dict[
        str,
        dict[str, Any],
    ] = {}

    missing: list[str] = []
    observations: list[dict[str, Any]] = []

    for header_name, configuration in SECURITY_HEADERS.items():
        value = normalized.get(
            header_name.lower()
        )

        present = bool(value)

        analyzed_headers[header_name] = {
            "present": present,
            "value": value if present else None,
        }

        if present:
            continue

        missing.append(header_name)

        observations.append(
            {
                "header": header_name,
                "severity": configuration["severity"],
                "title": f"Missing {header_name}",
                "description": configuration["description"],
                "evidence": (
                    f"{header_name} header was not observed."
                ),
            }
        )

    observations.sort(
        key=lambda item: (
            SEVERITY_ORDER.get(
                str(item["severity"]).lower(),
                99,
            ),
            str(item["title"]),
        )
    )

    counts = _severity_counts(
        observations
    )

    score = _risk_score(
        observations
    )

    grade = _calculate_grade(
        score
    )

    total_count = len(
        SECURITY_HEADERS
    )

    present_count = (
        total_count
        - len(missing)
    )

    return {
        "headers": analyzed_headers,
        "present_count": present_count,
        "missing_count": len(missing),
        "total_count": total_count,
        "missing": missing,
        "observations": observations,
        "risk_score": score,
        "grade": grade,
        "severity_counts": counts,
        "high_count": counts["high"],
        "medium_count": counts["medium"],
        "low_count": counts["low"],
        "observation_count": len(observations),
    }


def summarize_security(
    security_results: dict[int, dict[str, Any]],
) -> dict[str, Any]:
    """
    Combine security findings from multiple HTTP ports.

    Example input:

        {
            80: {
                "observations": [...]
            },
            443: {
                "observations": [...]
            }
        }

    Returns an overall security assessment.
    """

    all_observations: list[dict[str, Any]] = []

    for port, result in security_results.items():
        observations = result.get(
            "observations",
            [],
        )

        for observation in observations:
            item = dict(observation)

            item["port"] = port

            all_observations.append(item)

    counts = _severity_counts(
        all_observations
    )

    score = _risk_score(
        all_observations
    )

    grade = _calculate_grade(
        score
    )

    return {
        "risk_score": score,
        "grade": grade,
        "observation_count": len(
            all_observations
        ),
        "high_count": counts["high"],
        "medium_count": counts["medium"],
        "low_count": counts["low"],
        "observations": all_observations,
    }
