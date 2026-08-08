import argparse
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

from src.atlasscan.banner import grab_banner
from src.atlasscan.http import inspect_http
from src.atlasscan.report import generate_html_report
from src.atlasscan.scanner import scan_port
from src.atlasscan.service import identify_service
from src.atlasscan.technology import fingerprint_technology
from src.atlasscan.utils import parse_ports

console = Console()


def banner():
    console.print(
        Panel.fit(
            "[bold cyan]AtlasScan v1.0[/bold cyan]\n"
            "Professional Network Reconnaissance Toolkit",
            border_style="green",
        )
    )


def scan_with_progress(
    target: str,
    ports: list[int],
    timeout: float = 1.0,
    workers: int = 100,
) -> list[int]:
    """
    Scan ports while displaying live progress.
    """

    open_ports = []

    workers = max(1, min(workers, len(ports))) if ports else 1

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:

        task = progress.add_task(
            "[cyan]Scanning ports...",
            total=len(ports),
        )

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(
                    scan_port,
                    target,
                    port,
                    timeout,
                ): port
                for port in ports
            }

            for future in as_completed(futures):
                port = futures[future]

                try:
                    if future.result():
                        open_ports.append(port)
                except Exception:
                    pass

                progress.advance(task)

    return sorted(open_ports)


def collect_banners(
    target: str,
    open_ports: list[int],
    timeout: float = 2.0,
    workers: int = 20,
) -> dict[int, str | None]:
    """
    Collect banners from discovered open ports.
    """

    if not open_ports:
        return {}

    workers = max(1, min(workers, len(open_ports)))

    results = {}

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(
                grab_banner,
                target,
                port,
                timeout,
            ): port
            for port in open_ports
        }

        for future in as_completed(futures):
            port = futures[future]

            try:
                results[port] = future.result()
            except Exception:
                results[port] = None

    return dict(sorted(results.items()))


def build_service_results(
    open_ports: list[int],
    banners: dict[int, str | None],
) -> dict[int, dict[str, str]]:
    """
    Identify services from discovered ports and banners.
    """

    results = {}

    for port in open_ports:
        results[port] = identify_service(
            port,
            banners.get(port),
        )

    return results


def collect_http_details(
    target: str,
    open_ports: list[int],
    banners: dict[int, str | None],
) -> dict[int, dict[str, str | int | None]]:
    """
    Collect HTTP metadata from ports identified as HTTP services.
    """

    http_ports = []

    for port in open_ports:
        service_info = identify_service(
            port,
            banners.get(port),
        )

        if service_info["service"] in {"http", "https"}:
            http_ports.append(port)

    if not http_ports:
        return {}

    results = {}

    with ThreadPoolExecutor(
        max_workers=min(10, len(http_ports))
    ) as executor:
        futures = {
            executor.submit(
                inspect_http,
                target,
                port,
            ): port
            for port in http_ports
        }

        for future in as_completed(futures):
            port = futures[future]

            try:
                results[port] = future.result()
            except Exception:
                results[port] = {}

    return dict(sorted(results.items()))


def build_technology_results(
    open_ports: list[int],
    banners: dict[int, str | None],
    services: dict[int, dict[str, str]],
    http_details: dict[int, dict[str, str | int | None]],
) -> dict[int, list[dict[str, str]]]:
    """
    Fingerprint technologies for discovered services.
    """

    results = {}

    for port in open_ports:
        service_info = services[port]

        results[port] = fingerprint_technology(
            service=service_info["service"],
            version=service_info["version"],
            banner=banners.get(port),
            http_details=http_details.get(port),
        )

    return results


def save_json_report(
    filename: str,
    target: str,
    ports: list[int],
    open_ports: list[int],
    banners: dict[int, str | None],
    services: dict[int, dict[str, str]],
    http_details: dict[int, dict[str, str | int | None]],
    technologies: dict[int, list[dict[str, str]]],
    workers: int,
    timeout: float,
    elapsed: float,
):
    """
    Save scan results as a JSON report.
    """

    report = {
        "atlas_scan": {
            "version": "1.0",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target": target,
            "ports_scanned": len(ports),
            "open_ports": open_ports,
            "open_port_count": len(open_ports),
            "services": {
                str(port): services[port]
                for port in services
            },
            "banners": {
                str(port): banner
                for port, banner in banners.items()
            },
            "http": {
                str(port): details
                for port, details in http_details.items()
            },
            "technologies": {
                str(port): techs
                for port, techs in technologies.items()
            },
            "workers": workers,
            "timeout": timeout,
            "duration_seconds": round(elapsed, 4),
        }
    }

    output_path = Path(filename)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)


def main():
    parser = argparse.ArgumentParser(
        description="AtlasScan - Professional Network Reconnaissance Toolkit"
    )

    parser.add_argument(
        "target",
        help="Target IP address or hostname",
    )

    parser.add_argument(
        "-p",
        "--ports",
        default="21,22,80",
        help=(
            "Ports to scan "
            "(Examples: 22 | 22,80,443 | 1-100 | 20-25,80,443)"
        ),
    )

    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=1.0,
        help="Connection timeout in seconds (default: 1.0)",
    )

    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=100,
        help="Maximum concurrent workers (default: 100)",
    )

    parser.add_argument(
        "--json",
        metavar="FILE",
        help="Save scan results to a JSON file",
    )

    parser.add_argument(
        "--html",
        metavar="FILE",
        help="Save scan results to an HTML report",
    )

    args = parser.parse_args()

    if args.timeout <= 0:
        parser.error("timeout must be greater than 0")

    if args.workers <= 0:
        parser.error("workers must be greater than 0")

    banner()

    ports = parse_ports(args.ports)

    console.print(
        f"\n[bold cyan]Target:[/bold cyan] {args.target}"
    )

    console.print(
        f"[bold cyan]Ports:[/bold cyan] {len(ports)}"
    )

    console.print(
        f"[bold cyan]Workers:[/bold cyan] {args.workers}"
    )

    start_time = time.perf_counter()

    open_ports = scan_with_progress(
        args.target,
        ports,
        timeout=args.timeout,
        workers=args.workers,
    )

    banners = collect_banners(
        args.target,
        open_ports,
    )

    services = build_service_results(
        open_ports,
        banners,
    )

    http_details = collect_http_details(
        args.target,
        open_ports,
        banners,
    )

    technologies = build_technology_results(
        open_ports,
        banners,
        services,
        http_details,
    )

    elapsed = time.perf_counter() - start_time

    table = Table(title="Open Ports")

    table.add_column("Port", justify="center")
    table.add_column("Status", justify="center")
    table.add_column("Service", justify="center")
    table.add_column("Version", justify="center")
    table.add_column("Technologies", overflow="fold")

    if open_ports:
        for port in open_ports:
            service_info = services[port]

            service = service_info["service"]
            version = service_info["version"]

            tech_names = [
                tech["name"]
                for tech in technologies.get(port, [])
            ]

            technology_text = (
                ", ".join(tech_names)
                if tech_names
                else "Unknown"
            )

            table.add_row(
                str(port),
                "[green]OPEN[/green]",
                service,
                version,
                technology_text,
            )
    else:
        table.add_row(
            "-",
            "[red]No Open Ports Found[/red]",
            "-",
            "-",
            "-",
        )

    console.print()
    console.print(table)

    if http_details:
        http_table = Table(title="HTTP Details")

        http_table.add_column("Port", justify="center")
        http_table.add_column("Status", justify="center")
        http_table.add_column("Server")
        http_table.add_column("Content-Type")
        http_table.add_column("Content-Length")

        for port, details in http_details.items():
            http_table.add_row(
                str(port),
                str(details.get("status_code") or "Unknown"),
                str(details.get("server") or "Unknown"),
                str(details.get("content_type") or "Unknown"),
                str(details.get("content_length") or "Unknown"),
            )

        console.print()
        console.print(http_table)

    console.print(
        f"\n[bold green]Scan completed in "
        f"{elapsed:.2f} seconds[/bold green]"
    )

    if args.json:
        save_json_report(
            filename=args.json,
            target=args.target,
            ports=ports,
            open_ports=open_ports,
            banners=banners,
            services=services,
            http_details=http_details,
            technologies=technologies,
            workers=args.workers,
            timeout=args.timeout,
            elapsed=elapsed,
        )

        console.print(
            f"[bold green]JSON report saved:[/bold green] "
            f"{args.json}"
        )

    if args.html:
        generate_html_report(
            filename=args.html,
            target=args.target,
            ports_scanned=len(ports),
            open_ports=open_ports,
            services=services,
            banners=banners,
            http_details=http_details,
            technologies=technologies,
            duration=elapsed,
        )

        console.print(
            f"[bold green]HTML report saved:[/bold green] "
            f"{args.html}"
        )


if __name__ == "__main__":
    main()
