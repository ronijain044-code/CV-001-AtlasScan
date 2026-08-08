import argparse
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
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
from src.atlasscan.config import PROFILES, get_profile
from src.atlasscan.dns import resolve_dns
from src.atlasscan.http import inspect_http
from src.atlasscan.models import ScanResult
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


def collect_dns_details(
    target: str,
) -> dict:
    try:
        return resolve_dns(target)
    except Exception:
        return {
            "a": [],
            "aaaa": [],
            "ptr": {},
        }


def save_json_report(
    filename: str,
    result: ScanResult,
):
    report = {
        "atlas_scan": result.to_dict()
    }

    output_path = Path(filename)

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with output_path.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            report,
            file,
            indent=4,
        )


def display_dns_results(
    dns_data: dict,
):
    a_records = dns_data.get("a", [])
    aaaa_records = dns_data.get("aaaa", [])
    ptr_records = dns_data.get("ptr", {})

    if not a_records and not aaaa_records and not ptr_records:
        return

    dns_table = Table(
        title="DNS Records"
    )

    dns_table.add_column(
        "Type",
        justify="center",
    )

    dns_table.add_column(
        "Value"
    )

    for address in a_records:
        dns_table.add_row(
            "A",
            address,
        )

    for address in aaaa_records:
        dns_table.add_row(
            "AAAA",
            address,
        )

    for address, hostnames in ptr_records.items():
        for hostname in hostnames:
            dns_table.add_row(
                "PTR",
                f"{address} → {hostname}",
            )

    console.print()
    console.print(dns_table)


def main():
    parser = argparse.ArgumentParser(
        description=(
            "AtlasScan - Professional Network "
            "Reconnaissance Toolkit"
        )
    )

    parser.add_argument(
        "target",
        help="Target IP address or hostname",
    )

    parser.add_argument(
        "-p",
        "--ports",
        default=None,
        help=(
            "Ports to scan "
            "(Examples: 22 | 22,80,443 | "
            "1-100 | 20-25,80,443)"
        ),
    )

    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=None,
        help="Connection timeout in seconds",
    )

    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=None,
        help="Maximum concurrent workers",
    )

    parser.add_argument(
        "--profile",
        choices=sorted(PROFILES.keys()),
        help="Use a predefined scan profile",
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

    profile = None

    if args.profile:
        profile = get_profile(args.profile)

    if args.ports is not None:
        ports_spec = args.ports
    elif profile:
        ports_spec = profile.ports
    else:
        ports_spec = "21,22,80"

    if args.timeout is not None:
        timeout = args.timeout
    elif profile:
        timeout = profile.timeout
    else:
        timeout = 1.0

    if args.workers is not None:
        workers = args.workers
    elif profile:
        workers = profile.workers
    else:
        workers = 100

    if timeout <= 0:
        parser.error("timeout must be greater than 0")

    if workers <= 0:
        parser.error("workers must be greater than 0")

    banner()

    ports = parse_ports(ports_spec)

    console.print(
        f"\n[bold cyan]Target:[/bold cyan] {args.target}"
    )

    if profile:
        console.print(
            f"[bold cyan]Profile:[/bold cyan] {profile.name}"
        )

    console.print(
        f"[bold cyan]Ports:[/bold cyan] {len(ports)}"
    )

    console.print(
        f"[bold cyan]Workers:[/bold cyan] {workers}"
    )

    console.print(
        f"[bold cyan]Timeout:[/bold cyan] {timeout}s"
    )

    start_time = time.perf_counter()

    # DNS reconnaissance
    dns_data = collect_dns_details(
        args.target
    )

    # Port scanning
    open_ports = scan_with_progress(
        args.target,
        ports,
        timeout=timeout,
        workers=workers,
    )

    # Service banners
    banners = collect_banners(
        args.target,
        open_ports,
    )

    # Service identification
    services = build_service_results(
        open_ports,
        banners,
    )

    # HTTP inspection
    http_details = collect_http_details(
        args.target,
        open_ports,
        banners,
    )

    # Technology fingerprinting
    technologies = build_technology_results(
        open_ports,
        banners,
        services,
        http_details,
    )

    elapsed = time.perf_counter() - start_time

    # Unified result model
    result = ScanResult.create(
        target=args.target,
        ports_scanned=len(ports),
        workers=workers,
        timeout=timeout,
        profile=profile.name if profile else None,
    )

    result.open_ports = open_ports
    result.banners = banners
    result.services = services
    result.http = http_details
    result.technologies = technologies
    result.dns = dns_data
    result.duration_seconds = elapsed

    # Open ports table
    table = Table(
        title="Open Ports"
    )

    table.add_column(
        "Port",
        justify="center",
    )

    table.add_column(
        "Status",
        justify="center",
    )

    table.add_column(
        "Service",
        justify="center",
    )

    table.add_column(
        "Version",
        justify="center",
    )

    table.add_column(
        "Technologies",
        overflow="fold",
    )

    if result.open_ports:
        for port in result.open_ports:
            service_info = result.services[port]

            tech_names = [
                tech["name"]
                for tech in result.technologies.get(
                    port,
                    [],
                )
            ]

            technology_text = (
                ", ".join(tech_names)
                if tech_names
                else "Unknown"
            )

            table.add_row(
                str(port),
                "[green]OPEN[/green]",
                service_info["service"],
                service_info["version"],
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

    # HTTP details
    if result.http:
        http_table = Table(
            title="HTTP Details"
        )

        http_table.add_column(
            "Port",
            justify="center",
        )

        http_table.add_column(
            "Status",
            justify="center",
        )

        http_table.add_column(
            "Server"
        )

        http_table.add_column(
            "Content-Type"
        )

        http_table.add_column(
            "Content-Length"
        )

        for port, details in result.http.items():
            http_table.add_row(
                str(port),
                str(
                    details.get("status_code")
                    or "Unknown"
                ),
                str(
                    details.get("server")
                    or "Unknown"
                ),
                str(
                    details.get("content_type")
                    or "Unknown"
                ),
                str(
                    details.get("content_length")
                    or "Unknown"
                ),
            )

        console.print()
        console.print(http_table)

    # DNS details
    display_dns_results(
        result.dns
    )

    console.print(
        f"\n[bold green]Scan completed in "
        f"{result.duration_seconds:.2f} seconds[/bold green]"
    )

    if args.json:
        save_json_report(
            filename=args.json,
            result=result,
        )

        console.print(
            f"[bold green]JSON report saved:[/bold green] "
            f"{args.json}"
        )

    if args.html:
        generate_html_report(
            filename=args.html,
            result=result,
        )

        console.print(
            f"[bold green]HTML report saved:[/bold green] "
            f"{args.html}"
        )


if __name__ == "__main__":
    main()
