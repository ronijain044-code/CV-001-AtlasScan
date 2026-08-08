import argparse
import time

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

    from concurrent.futures import ThreadPoolExecutor, as_completed

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

    table = Table(title="Open Ports")

    table.add_column("Port", justify="center")
    table.add_column("Status", justify="center")

    if open_ports:
        for port in open_ports:
            table.add_row(
                str(port),
                "[green]OPEN[/green]",
            )
    else:
        table.add_row(
            "-",
            "[red]No Open Ports Found[/red]",
        )

    console.print()
    console.print(table)

    console.print(
        f"\n[bold green]Scan completed in "
        f"{elapsed:.2f} seconds[/bold green]"
    )


if __name__ == "__main__":
    main()
