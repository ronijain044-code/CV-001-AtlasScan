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
from src.atlasscan.risk import calculate_unified_risk
from src.atlasscan.scanner import scan_port
from src.atlasscan.security import analyze_security_headers
from src.atlasscan.service import identify_service
from src.atlasscan.subdomain import discover_subdomains
from src.atlasscan.technology import fingerprint_technology
from src.atlasscan.utils import parse_ports
from src.atlasscan.vulnerability import find_vulnerabilities
from src.atlasscan.webchecks import analyze_web_checks
from src.atlasscan.web import (
    check_robots,
    discover_common_paths,
    inspect_web,
)


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


def collect_subdomains(
    target: str,
) -> list[str]:
    try:
        return sorted(
            set(
                discover_subdomains(target)
                or []
            )
        )
    except Exception:
        return []


def collect_web_details(
    target: str,
    http_ports: list[int],
    timeout: float = 3.0,
) -> dict[int, dict]:
    """
    Perform deeper web reconnaissance against detected HTTP/HTTPS ports.
    """
    if not http_ports:
        return {}

    results: dict[int, dict] = {}

    workers = max(1, min(10, len(http_ports)))

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(
                inspect_web,
                target,
                port,
                timeout,
            ): port
            for port in http_ports
        }

        for future in as_completed(futures):
            port = futures[future]

            try:
                results[port] = future.result()
            except Exception as exc:
                results[port] = {
                    "status_code": None,
                    "url": None,
                    "final_url": None,
                    "title": None,
                    "server": None,
                    "content_type": None,
                    "content_length": None,
                    "allow": None,
                    "location": None,
                    "redirect": False,
                    "headers": {},
                    "security_headers": {},
                    "error": str(exc),
                }

    return dict(sorted(results.items()))


def collect_robots_details(
    target: str,
    http_ports: list[int],
    timeout: float = 3.0,
) -> dict[int, dict]:
    """
    Check robots.txt on detected HTTP/HTTPS ports.
    """
    if not http_ports:
        return {}

    results: dict[int, dict] = {}

    workers = max(1, min(10, len(http_ports)))

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(
                check_robots,
                target,
                port,
                timeout,
            ): port
            for port in http_ports
        }

        for future in as_completed(futures):
            port = futures[future]

            try:
                results[port] = future.result()
            except Exception as exc:
                results[port] = {
                    "url": None,
                    "status_code": None,
                    "exists": False,
                    "content": None,
                    "error": str(exc),
                }

    return dict(sorted(results.items()))


def collect_web_paths(
    target: str,
    http_ports: list[int],
    timeout: float = 3.0,
) -> dict[int, list[dict]]:
    """
    Discover a small set of common web paths.
    """
    if not http_ports:
        return {}

    results: dict[int, list[dict]] = {}

    workers = max(1, min(10, len(http_ports)))

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(
                discover_common_paths,
                target,
                port,
                timeout,
            ): port
            for port in http_ports
        }

        for future in as_completed(futures):
            port = futures[future]

            try:
                results[port] = future.result() or []
            except Exception:
                results[port] = []

    return dict(sorted(results.items()))


def collect_security_details(
    web_data: dict[int, dict],
) -> dict[int, dict]:
    """
    Analyze HTTP security headers and passive web-security checks
    for each inspected web service.
    """
    if not web_data:
        return {}

    results: dict[int, dict] = {}

    for port, details in web_data.items():
        if not isinstance(details, dict):
            continue

        headers = details.get("headers", {})
        status_code = details.get("status_code")
        url = details.get("url") or details.get("final_url")

        if not isinstance(headers, dict):
            headers = {}

        observations: list[dict] = []

        # ---------------------------------------------------------
        # Existing security-header analysis
        # ---------------------------------------------------------
        try:
            header_analysis = analyze_security_headers(headers)

            if isinstance(header_analysis, dict):
                header_observations = header_analysis.get(
                    "observations",
                    [],
                )

                if isinstance(header_observations, list):
                    observations.extend(
                        item
                        for item in header_observations
                        if isinstance(item, dict)
                    )

        except Exception:
            header_analysis = {
                "headers": {},
                "present_count": 0,
                "missing_count": 0,
                "total_count": 0,
                "missing": [],
                "observations": [],
            }

        # ---------------------------------------------------------
        # Passive web-security checks
        # ---------------------------------------------------------
        if (
            isinstance(status_code, int)
            and isinstance(url, str)
            and url
        ):
            try:
                web_check_result = analyze_web_checks(
                    status_code=status_code,
                    headers=headers,
                    url=url,
                )

                if isinstance(web_check_result, dict):
                    web_observations = web_check_result.get(
                        "observations",
                        [],
                    )

                    if isinstance(web_observations, list):
                        observations.extend(
                            item
                            for item in web_observations
                            if isinstance(item, dict)
                        )

            except Exception:
                pass

        # ---------------------------------------------------------
        # Deduplicate observations
        # ---------------------------------------------------------
        unique_observations: list[dict] = []
        seen_titles: set[str] = set()

        for observation in observations:
            if not isinstance(observation, dict):
                continue

            title = str(
                observation.get("title", "")
            ).strip().lower()

            # If there is no title, preserve the observation.
            if not title:
                unique_observations.append(observation)
                continue

            if title in seen_titles:
                continue

            seen_titles.add(title)
            unique_observations.append(observation)

        # ---------------------------------------------------------
        # Build combined security result
        # ---------------------------------------------------------
        result = dict(header_analysis)

        result["observations"] = unique_observations
        result["observation_count"] = len(
            unique_observations
        )

        # Preserve the passive web-check data.
        result["web_checks"] = (
            web_check_result
            if isinstance(
                locals().get("web_check_result"),
                dict,
            )
            else {}
        )

        results[port] = result

    return dict(sorted(results.items()))

def _vulnerability_product(
    service_info: dict,
    banner: str | None,
    technologies: list[dict],
) -> str | None:
    """Infer a product name suitable for local vulnerability matching."""
    for technology in technologies:
        name = str(technology.get("name") or "").strip()

        if name.lower().startswith("apache"):
            return "Apache HTTP Server"

        if name.lower().startswith("openssh"):
            return "OpenSSH"

    banner_text = str(banner or "")
    if "apache/" in banner_text.lower():
        return "Apache HTTP Server"

    service = str(service_info.get("service") or "").lower()
    if service == "http" and "apache" in banner_text.lower():
        return "Apache HTTP Server"

    return service_info.get("product")


def collect_vulnerability_details(
    open_ports: list[int],
    services: dict[int, dict[str, str]],
    banners: dict[int, str | None],
    technologies: dict[int, list[dict]],
) -> dict[int, list[dict]]:
    """Map detected service versions to curated potential vulnerabilities."""
    results: dict[int, list[dict]] = {}

    for port in open_ports:
        service_info = services.get(port, {})
        version = service_info.get("version")

        if not version or str(version).lower() == "unknown":
            continue

        product = _vulnerability_product(
            service_info,
            banners.get(port),
            technologies.get(port, []),
        )

        findings = find_vulnerabilities(
            product=product,
            version=version,
        )

        if findings:
            for finding in findings:
                finding["port"] = port

            results[port] = findings

    return dict(sorted(results.items()))


def display_vulnerability_results(
    vulnerabilities: dict[int, list[dict]],
):
    """Display potential vulnerability matches in the terminal."""
    if not vulnerabilities:
        return

    table = Table(title="Vulnerability Findings")

    table.add_column("Port", justify="center")
    table.add_column("CVE")
    table.add_column("Severity", justify="center")
    table.add_column("Product")
    table.add_column("Evidence")

    severity_styles = {
        "critical": "[bold red]CRITICAL[/bold red]",
        "high": "[red]HIGH[/red]",
        "medium": "[yellow]MEDIUM[/yellow]",
        "low": "[cyan]LOW[/cyan]",
    }

    for port, findings in vulnerabilities.items():
        for finding in findings:
            severity = str(
                finding.get("severity", "unknown")
            ).lower()

            table.add_row(
                str(port),
                str(finding.get("cve") or "Unknown"),
                severity_styles.get(
                    severity,
                    severity.upper(),
                ),
                str(finding.get("product") or "Unknown"),
                str(finding.get("evidence") or "Unknown"),
            )

    console.print()
    console.print(table)


def save_json_report(
    filename: str,
    result: ScanResult,
):
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
            result.to_report(),
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


def display_subdomain_results(
    subdomains: list[str],
):
    if not subdomains:
        return

    table = Table(
        title="Discovered Subdomains"
    )

    table.add_column(
        "#",
        justify="center",
    )

    table.add_column(
        "Subdomain"
    )

    for index, subdomain in enumerate(
        subdomains,
        start=1,
    ):
        table.add_row(
            str(index),
            subdomain,
        )

    console.print()
    console.print(table)


def display_web_results(
    web_data: dict[int, dict],
):
    if not web_data:
        return

    table = Table(
        title="Web Inspection"
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
        "Title",
    )

    table.add_column(
        "Server",
    )

    table.add_column(
        "Content-Type",
    )

    table.add_column(
        "Redirect",
        justify="center",
    )

    for port, details in web_data.items():
        status = details.get("status_code")

        table.add_row(
            str(port),
            str(status or "Unknown"),
            str(details.get("title") or "Unknown"),
            str(details.get("server") or "Unknown"),
            str(details.get("content_type") or "Unknown"),
            "Yes" if details.get("redirect") else "No",
        )

    console.print()
    console.print(table)


def display_security_headers(
    web_data: dict[int, dict],
):
    if not web_data:
        return

    table = Table(
        title="Security Headers"
    )

    table.add_column(
        "Port",
        justify="center",
    )

    table.add_column(
        "Header",
    )

    table.add_column(
        "Value",
    )

    found = False

    for port, details in web_data.items():
        security_headers = details.get(
            "security_headers",
            {},
        )

        for header, value in security_headers.items():
            if value:
                found = True

                table.add_row(
                    str(port),
                    header,
                    str(value),
                )

    if found:
        console.print()
        console.print(table)


def display_security_findings(
    security_data: dict[int, dict],
):
    """Display security-header observations in the terminal."""
    if not security_data:
        return

    table = Table(
        title="Security Findings"
    )

    table.add_column("Port", justify="center")
    table.add_column("Severity", justify="center")
    table.add_column("Finding")
    table.add_column("Evidence")

    found = False

    severity_styles = {
        "high": "[red]HIGH[/red]",
        "medium": "[yellow]MEDIUM[/yellow]",
        "low": "[cyan]LOW[/cyan]",
    }

    for port, details in security_data.items():
        observations = details.get("observations", [])

        for observation in observations:
            found = True
            severity = str(
                observation.get("severity", "unknown")
            ).lower()

            severity_text = severity_styles.get(
                severity,
                severity.upper(),
            )

            table.add_row(
                str(port),
                severity_text,
                str(observation.get("title") or "Unknown"),
                str(observation.get("evidence") or "Unknown"),
            )

    if found:
        console.print()
        console.print(table)


def display_robots_results(
    robots_data: dict[int, dict],
):
    if not robots_data:
        return

    table = Table(
        title="Robots.txt"
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
        "Exists",
        justify="center",
    )

    table.add_column(
        "URL",
    )

    for port, details in robots_data.items():
        table.add_row(
            str(port),
            str(details.get("status_code") or "Unknown"),
            "Yes" if details.get("exists") else "No",
            str(details.get("url") or "Unknown"),
        )

    console.print()
    console.print(table)


def display_web_path_results(
    web_paths: dict[int, list[dict]],
):
    if not web_paths:
        return

    table = Table(
        title="Discovered Web Paths"
    )

    table.add_column(
        "Port",
        justify="center",
    )

    table.add_column(
        "Path",
    )

    table.add_column(
        "Status",
        justify="center",
    )

    table.add_column(
        "Content-Type",
    )

    for port, paths in web_paths.items():
        for path_info in paths:
            table.add_row(
                str(port),
                str(path_info.get("path") or "/"),
                str(
                    path_info.get("status_code")
                    or "Unknown"
                ),
                str(
                    path_info.get("content_type")
                    or "Unknown"
                ),
            )

    console.print()
    console.print(table)


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

    # ---------------------------------------------------------
    # DNS reconnaissance
    # ---------------------------------------------------------
    dns_data = collect_dns_details(
        args.target
    )

    # ---------------------------------------------------------
    # Subdomain discovery
    # ---------------------------------------------------------
    subdomains = collect_subdomains(
        args.target
    )

    # ---------------------------------------------------------
    # Port scanning
    # ---------------------------------------------------------
    open_ports = scan_with_progress(
        args.target,
        ports,
        timeout=timeout,
        workers=workers,
    )

    # ---------------------------------------------------------
    # Service banners
    # ---------------------------------------------------------
    banners = collect_banners(
        args.target,
        open_ports,
    )

    # ---------------------------------------------------------
    # Service identification
    # ---------------------------------------------------------
    services = build_service_results(
        open_ports,
        banners,
    )

    # ---------------------------------------------------------
    # HTTP inspection
    # ---------------------------------------------------------
    http_details = collect_http_details(
        args.target,
        open_ports,
        banners,
    )

    # ---------------------------------------------------------
    # Technology fingerprinting
    # ---------------------------------------------------------
    technologies = build_technology_results(
        open_ports,
        banners,
        services,
        http_details,
    )

    # ---------------------------------------------------------
    # Vulnerability intelligence
    # ---------------------------------------------------------
    vulnerabilities = collect_vulnerability_details(
        open_ports,
        services,
        banners,
        technologies,
    )

    # ---------------------------------------------------------
    # Determine HTTP/HTTPS ports
    # ---------------------------------------------------------
    http_ports = sorted(
        port
        for port in open_ports
        if services.get(port, {}).get("service")
        in {"http", "https"}
    )

    # ---------------------------------------------------------
    # Deep web inspection
    # ---------------------------------------------------------
    web_details = collect_web_details(
        args.target,
        http_ports,
        timeout=max(3.0, timeout),
    )

    # ---------------------------------------------------------
    # Security analysis
    # ---------------------------------------------------------
    security_details = collect_security_details(
        web_details
    )

    # ---------------------------------------------------------
    # robots.txt
    # ---------------------------------------------------------
    robots_details = collect_robots_details(
        args.target,
        http_ports,
        timeout=max(3.0, timeout),
    )

    # ---------------------------------------------------------
    # Common web paths
    # ---------------------------------------------------------
    web_paths = collect_web_paths(
        args.target,
        http_ports,
        timeout=max(3.0, timeout),
    )

    elapsed = time.perf_counter() - start_time

    # ---------------------------------------------------------
    # Unified result model
    # ---------------------------------------------------------
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
    result.subdomains = subdomains

    # New web reconnaissance data
    result.web = web_details
    result.robots = robots_details
    result.web_paths = web_paths
    result.security = security_details
    result.vulnerabilities = vulnerabilities

    # Unified risk assessment
    unified_risk = calculate_unified_risk(
    security=result.security,
    vulnerabilities=result.vulnerabilities,
    )

    result.unified_risk = unified_risk

    result.duration_seconds = elapsed

    # ---------------------------------------------------------
    # Open ports table
    # ---------------------------------------------------------
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

    # ---------------------------------------------------------
    # HTTP details
    # ---------------------------------------------------------
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

    # ---------------------------------------------------------
    # DNS details
    # ---------------------------------------------------------
    display_dns_results(
        result.dns
    )

    # ---------------------------------------------------------
    # Subdomain details
    # ---------------------------------------------------------
    display_subdomain_results(
        result.subdomains
    )

    # ---------------------------------------------------------
    # Deep web inspection
    # ---------------------------------------------------------
    display_web_results(
        result.web
    )

    # ---------------------------------------------------------
    # Security headers
    # ---------------------------------------------------------
    display_security_headers(
        result.web
    )

    # ---------------------------------------------------------
    # Security findings
    # ---------------------------------------------------------
    display_security_findings(
        result.security
    )

    # ---------------------------------------------------------
    # Vulnerability intelligence
    # ---------------------------------------------------------
    display_vulnerability_results(
        result.vulnerabilities
    )

    # ---------------------------------------------------------
    # robots.txt
    # ---------------------------------------------------------
    display_robots_results(
        result.robots
    )

    # ---------------------------------------------------------
    # Common web paths
    # ---------------------------------------------------------
    display_web_path_results(
        result.web_paths
    )

    # ---------------------------------------------------------
    # Completion
    # ---------------------------------------------------------
    console.print(
        f"\n[bold green]Scan completed in "
        f"{result.duration_seconds:.2f} seconds[/bold green]"
    )

    # ---------------------------------------------------------
    # JSON report
    # ---------------------------------------------------------
    if args.json:
        save_json_report(
            filename=args.json,
            result=result,
        )

        console.print(
            f"[bold green]JSON report saved:[/bold green] "
            f"{args.json}"
        )

    # ---------------------------------------------------------
    # HTML report
    # ---------------------------------------------------------
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
