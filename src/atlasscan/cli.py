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
from src.atlasscan.scanner import scan_port
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
                executor.submit(scan_port, target, port, timeout): port
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


def save_json_report(
    filename: str,
    target: str,
    ports: list[int],
    open_ports: list[int],
    banners: dict[int, str | None],
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
            "banners": {
                str(port): banner
                for port, banner in banners.items()
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

    elapsed = time.perf_counter() - start_time

    banners = collect_banners(
        args.target,
        open_ports,
    )

    table = Table(title="Open Ports")

    table.add_column("Port", justify="center")
    table.add_column("Status", justify="center")
    table.add_column("Banner", overflow="fold")

    if open_ports:
        for port in open_ports:
            service_banner = banners.get(port)

            if service_banner:
                service_banner = service_banner.replace(
                    "\r",
                    " ",
                ).replace(
                    "\n",
                    " ",
                )

                if len(service_banner) > 80:
                    service_banner = service_banner[:77] + "..."

            else:
                service_banner = "No banner"

            table.add_row(
                str(port),
                "[green]OPEN[/green]",
                service_banner,
            )
    else:
        table.add_row(
            "-",
            "[red]No Open Ports Found[/red]",
            "-",
        )

    console.print()
    console.print(table)

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
            workers=args.workers,
            timeout=args.timeout,
            elapsed=elapsed,
        )

        console.print(
            f"[bold green]JSON report saved:[/bold green] "
            f"{args.json}"
        )


if __name__ == "__main__":
    main()
