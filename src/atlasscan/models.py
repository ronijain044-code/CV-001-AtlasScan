from __future__ import annotations

from dataclasses import asdict, dataclass, field
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
    technologies: dict[int, list[dict[str, Any]]] = field(
        default_factory=dict
    )
    dns: dict[str, Any] = field(default_factory=dict)
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
            len(technologies)
            for technologies in self.technologies.values()
        )

    @property
    def dns_record_count(self) -> int:
        count = 0

        for values in self.dns.values():
            if isinstance(values, dict):
                count += sum(
                    len(items)
                    for items in values.values()
                    if isinstance(items, list)
                )
            elif isinstance(values, list):
                count += len(values)

        return count

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)

        data["open_port_count"] = self.open_port_count
        data["technology_count"] = self.technology_count
        data["dns_record_count"] = self.dns_record_count

        return data

    def to_report(self) -> dict[str, Any]:
        return {
            "atlas_scan": self.to_dict()
        }
