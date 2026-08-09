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
    services: dict[int, dict[str, Any]] = field(default_factory=dict)
    banners: dict[int, str | None] = field(default_factory=dict)
    http: dict[int, dict[str, Any]] = field(default_factory=dict)
    technologies: dict[int, list[dict[str, Any]]] = field(default_factory=dict)
    dns: dict[str, Any] = field(default_factory=dict)
    subdomains: list[str] = field(default_factory=list)
    web: dict[int, dict[str, Any]] = field(default_factory=dict)
    security: dict[int, dict[str, Any]] = field(default_factory=dict)
    web_paths: dict[int, list[dict[str, Any]]] = field(default_factory=dict)
    robots: dict[int, dict[str, Any]] = field(default_factory=dict)
    vulnerabilities: dict[int, list[dict[str, Any]]] = field(default_factory=dict)
    unified_risk: dict[str, Any] = field(default_factory=dict)
    workers: int = 100
    timeout: float = 1.0
    duration_seconds: float = 0.0
    profile: str | None = None

    @classmethod
    def create(
        cls,
        target: str,
        ports_scanned: int,
        workers: int,
        timeout: float,
        profile: str | None = None,
    ) -> "ScanResult":
        return cls(
            target=target,
            timestamp=datetime.now(timezone.utc).isoformat(),
            ports_scanned=ports_scanned,
            workers=workers,
            timeout=timeout,
            profile=profile,
        )

    @property
    def open_port_count(self) -> int:
        return len(self.open_ports)

    @property
    def technology_count(self) -> int:
        return sum(
            len(items)
            for items in self.technologies.values()
        )

    @property
    def dns_record_count(self) -> int:
        count = 0

        for value in self.dns.values():
            if isinstance(value, list):
                count += len(value)
            elif isinstance(value, dict):
                for nested in value.values():
                    if isinstance(nested, list):
                        count += len(nested)
                    else:
                        count += 1
            elif value is not None:
                count += 1

        return count

    @property
    def subdomain_count(self) -> int:
        return len(self.subdomains)

    @property
    def web_count(self) -> int:
        return len(self.web)

    @property
    def web_path_count(self) -> int:
        """Return the total number of discovered web paths."""
        total = 0

        for paths in self.web_paths.values():
            if isinstance(paths, list):
                total += len(paths)

        return total

    @property
    def security_observation_count(self) -> int:
        total = 0

        for details in self.security.values():
            observations = details.get("observations", [])

            if isinstance(observations, list):
                total += len(observations)

        return total

    @property
    def security_high_count(self) -> int:
        count = 0

        for details in self.security.values():
            for observation in details.get("observations", []):
                if observation.get("severity") == "high":
                    count += 1

        return count

    @property
    def security_medium_count(self) -> int:
        count = 0

        for details in self.security.values():
            for observation in details.get("observations", []):
                if observation.get("severity") == "medium":
                    count += 1

        return count

    @property
    def security_risk_score(self) -> int:
        """Return the aggregate security-header risk score."""
        total = 0

        for details in self.security.values():
            try:
                total += int(details.get("risk_score", 0) or 0)
            except (TypeError, ValueError):
                continue

        return total

    @property
    def security_grade(self) -> str:
        """Return a letter grade derived from the aggregate security risk."""
        score = self.security_risk_score

        if score <= 2:
            return "A"
        if score <= 5:
            return "B"
        if score <= 8:
            return "C"
        if score <= 12:
            return "D"
        return "F"

    @property
    def vulnerability_count(self) -> int:
        """Return the total number of potential vulnerability matches."""
        return sum(
            len(findings)
            for findings in self.vulnerabilities.values()
            if isinstance(findings, list)
        )

    @property
    def vulnerability_critical_count(self) -> int:
        return self._vulnerability_severity_count("critical")

    @property
    def vulnerability_high_count(self) -> int:
        return self._vulnerability_severity_count("high")

    @property
    def vulnerability_medium_count(self) -> int:
        return self._vulnerability_severity_count("medium")

    @property
    def vulnerability_low_count(self) -> int:
        return self._vulnerability_severity_count("low")

    def _vulnerability_severity_count(self, severity: str) -> int:
        count = 0

        for findings in self.vulnerabilities.values():
            if not isinstance(findings, list):
                continue

            for finding in findings:
                if str(finding.get("severity", "")).lower() == severity:
                    count += 1

        return count


    @property
    def security_low_count(self) -> int:
        count = 0

        for details in self.security.values():
            for observation in details.get("observations", []):
                if observation.get("severity") == "low":
                    count += 1

        return count

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "timestamp": self.timestamp,
            "ports_scanned": self.ports_scanned,
            "open_ports": self.open_ports,
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
            "subdomains": self.subdomains,
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
            "vulnerabilities": {
                str(port): value
                for port, value in self.vulnerabilities.items()
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
            "security_observation_count": self.security_observation_count,
            "security_high_count": self.security_high_count,
            "security_medium_count": self.security_medium_count,
            "security_low_count": self.security_low_count,
            "security_risk_score": self.security_risk_score,
            "security_grade": self.security_grade,
            "vulnerability_count": self.vulnerability_count,
            "vulnerability_critical_count": self.vulnerability_critical_count,
            "vulnerability_high_count": self.vulnerability_high_count,
            "vulnerability_medium_count": self.vulnerability_medium_count,
            "vulnerability_low_count": self.vulnerability_low_count,
            "unified_risk": self.unified_risk,
        }

    def to_report(self) -> dict[str, Any]:
        return {
            "atlas_scan": self.to_dict()
        }

    def __repr__(self) -> str:
        return (
            f"ScanResult("
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
            f")"
        )
