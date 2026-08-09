from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class ScanResult:
    target: str
    timestamp: str
    ports_scanned: int

    open_ports: list[int] = field(
        default_factory=list
    )

    services: dict[int, dict[str, Any]] = field(
        default_factory=dict
    )

    banners: dict[int, str | None] = field(
        default_factory=dict
    )

    http: dict[int, dict[str, Any]] = field(
        default_factory=dict
    )

    technologies: dict[
        int,
        list[dict[str, Any]]
    ] = field(
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

    robots: dict[int, dict[str, Any]] = field(
        default_factory=dict
    )

    web_paths: dict[
        int,
        list[dict[str, Any]]
    ] = field(
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
        workers: int,
        timeout: float,
        profile: str | None = None,
    ) -> "ScanResult":
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
        return len(self.open_ports)

    @property
    def technology_count(self) -> int:
        return sum(
            len(technologies)
            for technologies
            in self.technologies.values()
        )

    @property
    def dns_record_count(self) -> int:
        count = 0

        for record_type, values in self.dns.items():

            if record_type == "ptr":
                if isinstance(values, dict):
                    count += sum(
                        len(records)
                        if isinstance(records, list)
                        else 1
                        for records
                        in values.values()
                    )

                continue

            if isinstance(values, list):
                count += len(values)

            elif values:
                count += 1

        return count

    @property
    def subdomain_count(self) -> int:
        return len(self.subdomains)

    @property
    def web_count(self) -> int:
        return len(self.web)

    @property
    def robots_count(self) -> int:
        return sum(
            1
            for result in self.robots.values()
            if (
                isinstance(result, dict)
                and result.get("exists")
            )
        )

    @property
    def web_path_count(self) -> int:
        return sum(
            len(paths)
            for paths in self.web_paths.values()
        )

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)

        data["open_port_count"] = (
            self.open_port_count
        )

        data["technology_count"] = (
            self.technology_count
        )

        data["dns_record_count"] = (
            self.dns_record_count
        )

        data["subdomain_count"] = (
            self.subdomain_count
        )

        data["web_count"] = (
            self.web_count
        )

        data["robots_count"] = (
            self.robots_count
        )

        data["web_path_count"] = (
            self.web_path_count
        )

        return data

    def to_report(self) -> dict[str, Any]:
        return {
            "atlas_scan": self.to_dict()
        }

    def __repr__(self) -> str:
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
            f"robots={self.robots!r}, "
            f"web_paths={self.web_paths!r}, "
            f"workers={self.workers}, "
            f"timeout={self.timeout}, "
            f"duration_seconds={self.duration_seconds}, "
            f"profile={self.profile!r}"
            ")"
        )
