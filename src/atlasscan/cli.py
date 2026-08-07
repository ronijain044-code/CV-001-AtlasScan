import argparse

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from src.atlasscan.scanner import scan_ports
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
        help="Ports to scan (Examples: 22 | 22,80,443 | 1-100 | 20-25,80,443)",
    )

    args = parser.parse_args()

    banner()

    console.print(f"\n[bold cyan]Target:[/bold cyan] {args.target}")

    ports = parse_ports(args.ports)

    console.print(f"[bold cyan]Scanning:[/bold cyan] {len(ports)} ports\n")

    open_ports = scan_ports(args.target, ports)

    table = Table(title="Open Ports")

    table.add_column("Port", justify="center")
    table.add_column("Status", justify="center")

    if open_ports:
        for port in open_ports:
            table.add_row(str(port), "[green]OPEN[/green]")
    else:
        table.add_row("-", "[red]No Open Ports Found[/red]")

    console.print(table)


if __name__ == "__main__":
    main()
