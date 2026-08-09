from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class ScanResult:
    target: str
    timestamp: str

    ports_scanned: int

    open_ports: list[int] = field(default_factory=list)

    services: dict[int, dict[str, Any]] = field(
        default_factory=dict
    )

    banners: dict[int, str | None] = field(
        default_factory=dict
    )

    http: dict[int, dict[str, Any]] = field(
        default_factory=dict
    )

    technologies: dict[int, list[dict[str, Any]]] = field(
        default_factory=dict
    )

    dns: dict[str, Any] = field(
        default_factory=dict
    )

    subdomains: list[str] = field(
        default_factory=list
    )

    web: dict[int, dict[str, Any]] = field(
        default_factory=dict
    )

    security: dict[int, dict[str, Any]] = field(
        default_factory=dict
    )

    web_paths: dict[int, list[dict[str, Any]]] = field(
        default_factory=dict
    )

    robots: dict[int, dict[str, Any]] = field(
        default_factory=dict
    )

    workers: int = 100

    timeout: float = 1.0

    duration_seconds: float = 0.0

    profile: str | None = None

    @classmethod
    def create(
        cls,
        target: str,
        ports_scanned: int,
        workers: int = 100,
        timeout: float = 1.0,
        profile: str | None = None,
    ) -> "ScanResult":
        """
        Create a new ScanResult with a UTC timestamp.
        """

        return cls(
            target=target,
            timestamp=datetime.now(
                timezone.utc
            ).isoformat(),
            ports_scanned=ports_scanned,
            workers=workers,
            timeout=timeout,
            profile=profile,
        )

    @property
    def open_port_count(self) -> int:
        """
        Return the number of open ports.
        """

        return len(self.open_ports)

    @property
    def technology_count(self) -> int:
        """
        Return the total number of detected technologies.
        """

        return sum(
            len(items)
            for items in self.technologies.values()
        )

    @property
    def dns_record_count(self) -> int:
        """
        Return the number of DNS records.
        """

        count = 0

        if not self.dns:
            return 0

        for record_type, values in self.dns.items():

            if record_type == "ptr":
                if isinstance(values, dict):
                    for ptr_values in values.values():
                        if isinstance(
                            ptr_values,
                            list,
                        ):
                            count += len(
                                ptr_values
                            )

                        elif ptr_values:
                            count += 1

                continue

            if isinstance(values, list):
                count += len(values)

            elif values:
                count += 1

        return count

    @property
    def subdomain_count(self) -> int:
        """
        Return the number of discovered subdomains.
        """

        return len(self.subdomains)

    @property
    def web_count(self) -> int:
        """
        Return the number of web inspections.
        """

        return len(self.web)

    @property
    def web_path_count(self) -> int:
        """
        Return the total number of discovered web paths.
        """

        return sum(
            len(paths)
            for paths in self.web_paths.values()
        )

    @property
    def security_observation_count(self) -> int:
        """
        Return the total number of security observations.
        """

        count = 0

        for result in self.security.values():
            observations = result.get(
                "observations",
                [],
            )

            if isinstance(
                observations,
                list,
            ):
                count += len(observations)

        return count

    @property
    def security_high_count(self) -> int:
        """
        Return the number of HIGH security findings.
        """

        return self._security_severity_count(
            "high"
        )

    @property
    def security_medium_count(self) -> int:
        """
        Return the number of MEDIUM security findings.
        """

        return self._security_severity_count(
            "medium"
        )

    @property
    def security_low_count(self) -> int:
        """
        Return the number of LOW security findings.
        """

        return self._security_severity_count(
            "low"
        )

    def _security_severity_count(
        self,
        severity: str,
    ) -> int:
        """
        Count security findings of a specific severity.
        """

        count = 0

        for result in self.security.values():

            observations = result.get(
                "observations",
                [],
            )

            if not isinstance(
                observations,
                list,
            ):
                continue

            for observation in observations:

                if (
                    str(
                        observation.get(
                            "severity",
                            "",
                        )
                    ).lower()
                    == severity.lower()
                ):
                    count += 1

        return count

    @property
    def security_risk_score(self) -> int:
        """
        Return the overall security risk score.

        The score is expected to be supplied by the security
        analyzer. If no analyzer result exists, return 100.
        """

        if not self.security:
            return 100

        scores: list[int] = []

        for result in self.security.values():

            score = result.get(
                "risk_score"
            )

            if isinstance(
                score,
                int,
            ):
                scores.append(score)

            elif isinstance(
                score,
                float,
            ):
                scores.append(
                    int(score)
                )

        if not scores:
            return 100

        return min(scores)

    @property
    def security_grade(self) -> str:
        """
        Return the overall security grade.

        A: 90-100
        B: 80-89
        C: 70-79
        D: 60-69
        F: 0-59
        """

        score = self.security_risk_score

        if score >= 90:
            return "A"

        if score >= 80:
            return "B"

        if score >= 70:
            return "C"

        if score >= 60:
            return "D"

        return "F"

    def to_dict(self) -> dict[str, Any]:
        """
        Convert the scan result into a JSON-compatible dictionary.
        """

        return {
            "target": self.target,
            "timestamp": self.timestamp,
            "ports_scanned": self.ports_scanned,
            "open_ports": list(
                self.open_ports
            ),
            "services": {
                str(port): value
                for port, value in self.services.items()
            },
            "banners": {
                str(port): value
                for port, value in self.banners.items()
            },
            "http": {
                str(port): value
                for port, value in self.http.items()
            },
            "technologies": {
                str(port): value
                for port, value in self.technologies.items()
            },
            "dns": self.dns,
            "subdomains": list(
                self.subdomains
            ),
            "web": {
                str(port): value
                for port, value in self.web.items()
            },
            "security": {
                str(port): value
                for port, value in self.security.items()
            },
            "web_paths": {
                str(port): value
                for port, value in self.web_paths.items()
            },
            "robots": {
                str(port): value
                for port, value in self.robots.items()
            },
            "workers": self.workers,
            "timeout": self.timeout,
            "duration_seconds": self.duration_seconds,
            "profile": self.profile,

            "open_port_count": self.open_port_count,
            "technology_count": self.technology_count,
            "dns_record_count": self.dns_record_count,
            "subdomain_count": self.subdomain_count,
            "web_count": self.web_count,
            "web_path_count": self.web_path_count,

            "security_observation_count": (
                self.security_observation_count
            ),

            "security_high_count": (
                self.security_high_count
            ),

            "security_medium_count": (
                self.security_medium_count
            ),

            "security_low_count": (
                self.security_low_count
            ),

            "security_risk_score": (
                self.security_risk_score
            ),

            "security_grade": (
                self.security_grade
            ),
        }

    def to_report(self) -> dict[str, Any]:
        """
        Return the complete report representation.

        Kept as a compatibility alias for existing CLI/report
        code.
        """

        return self.to_dict()

    def __repr__(self) -> str:
        """
        Compact developer-friendly representation.
        """

        return (
            "ScanResult("
            f"target={self.target!r}, "
            f"timestamp={self.timestamp!r}, "
            f"ports_scanned={self.ports_scanned}, "
            f"open_ports={self.open_ports!r}, "
            f"services={self.services!r}, "
            f"banners={self.banners!r}, "
            f"http={self.http!r}, "
            f"technologies={self.technologies!r}, "
            f"dns={self.dns!r}, "
            f"subdomains={self.subdomains!r}, "
            f"web={self.web!r}, "
            f"security={self.security!r}, "
            f"web_paths={self.web_paths!r}, "
            f"robots={self.robots!r}, "
            f"workers={self.workers}, "
            f"timeout={self.timeout}, "
            f"duration_seconds={self.duration_seconds}, "
            f"profile={self.profile!r}"
            ")"
        )
