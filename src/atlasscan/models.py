from dataclasses import asdict, dataclass, field
from datetime import datetime


@dataclass
class ScanResult:
    """
    Central data model containing the complete result of an AtlasScan run.
    """

    target: str
    timestamp: str
    ports_scanned: int
    open_ports: list[int] = field(default_factory=list)
    services: dict[int, dict[str, str]] = field(
        default_factory=dict
    )
    banners: dict[int, str | None] = field(
        default_factory=dict
    )
    http: dict[int, dict[str, str | int | None]] = field(
        default_factory=dict
    )
    technologies: dict[
        int,
        list[dict[str, str]],
    ] = field(default_factory=dict)
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
        """
        Create a new ScanResult with a timezone-aware timestamp.
        """

        return cls(
            target=target,
            timestamp=datetime.now().astimezone().isoformat(),
            ports_scanned=ports_scanned,
            workers=workers,
            timeout=timeout,
            profile=profile,
        )

    @property
    def open_port_count(self) -> int:
        """
        Return the number of discovered open ports.
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

    def to_dict(self) -> dict:
        """
        Convert the scan result into a JSON-compatible dictionary.
        """

        data = asdict(self)

        data["open_port_count"] = self.open_port_count

        data["technology_count"] = self.technology_count

        data["services"] = {
            str(port): service
            for port, service in self.services.items()
        }

        data["banners"] = {
            str(port): banner
            for port, banner in self.banners.items()
        }

        data["http"] = {
            str(port): details
            for port, details in self.http.items()
        }

        data["technologies"] = {
            str(port): technologies
            for port, technologies in self.technologies.items()
        }

        return data
