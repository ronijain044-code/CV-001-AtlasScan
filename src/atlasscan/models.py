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