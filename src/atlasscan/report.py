import html
from pathlib import Path

from src.atlasscan.models import ScanResult


def _escape(value: object) -> str:
    """Safely escape a value for HTML output."""
    return html.escape(str(value))


def generate_html_report(
    filename: str,
    result: ScanResult | None = None,
    *,
    target: str | None = None,
    ports_scanned: int | None = None,
    open_ports: list[int] | None = None,
    services: dict[int, dict[str, str]] | None = None,
    banners: dict[int, str | None] | None = None,
    http_details: dict[int, dict[str, str | int | None]] | None = None,
    technologies: dict[int, list[dict[str, str]]] | None = None,
    dns: dict | None = None,
    subdomains: list[str] | None = None,
    duration: float | None = None,
) -> None:
    """
    Generate a professional HTML report.

    Supports both the ScanResult-based API and the
    legacy keyword-based API.
    """

    if result is None:
        result = ScanResult.create(
            target=target or "Unknown",
            ports_scanned=ports_scanned or 0,
            workers=100,
            timeout=1.0,
        )

        result.open_ports = open_ports or []
        result.services = services or {}
        result.banners = banners or {}
        result.http = http_details or {}
        result.technologies = technologies or {}
        result.dns = dns or {}
        result.subdomains = subdomains or []
        result.duration_seconds = duration or 0.0

    output_path = Path(filename)

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    # Open ports
    rows = []

    for port in result.open_ports:
        service = result.services.get(
            port,
            {},
        )

        technologies_for_port = result.technologies.get(
            port,
            [],
        )

        technology_names = ", ".join(
            tech.get("name", "Unknown")
            for tech in technologies_for_port
        )

        if not technology_names:
            technology_names = "Unknown"

        banner = result.banners.get(port)

        if not banner:
            banner = "No banner"

        rows.append(
            f"""
            <tr>
                <td>{_escape(port)}</td>
                <td class="open">OPEN</td>
                <td>{_escape(service.get("service", "unknown"))}</td>
                <td>{_escape(service.get("version", "unknown"))}</td>
                <td>{_escape(technology_names)}</td>
                <td class="banner">{_escape(banner)}</td>
            </tr>
            """
        )

    if not rows:
        rows.append(
            """
            <tr>
                <td colspan="6" class="empty">
                    No open ports discovered
                </td>
            </tr>
            """
        )

    # HTTP
    http_rows = []

    for port, details in result.http.items():
        http_rows.append(
            f"""
            <tr>
                <td>{_escape(port)}</td>
                <td>{_escape(details.get("status_code", "Unknown"))}</td>
                <td>{_escape(details.get("server", "Unknown"))}</td>
                <td>{_escape(details.get("content_type", "Unknown"))}</td>
                <td>{_escape(details.get("content_length", "Unknown"))}</td>
            </tr>
            """
        )

    if not http_rows:
        http_rows.append(
            """
            <tr>
                <td colspan="5" class="empty">
                    No HTTP services detected
                </td>
            </tr>
            """
        )

    # Technologies
    technology_cards = []

    for port, technologies_for_port in result.technologies.items():
        for technology in technologies_for_port:
            technology_cards.append(
                f"""
                <div class="tech-card">
                    <div class="tech-name">
                        {_escape(technology.get("name", "Unknown"))}
                    </div>

                    <div class="tech-category">
                        Category:
                        {_escape(
                            technology.get(
                                "category",
                                "Unknown",
                            )
                        )}
                    </div>

                    <div class="tech-source">
                        Detected from:
                        {_escape(
                            technology.get(
                                "detected_from",
                                "Unknown",
                            )
                        )}
                    </div>

                    <div class="tech-port">
                        Port:
                        {_escape(port)}
                    </div>
                </div>
                """
            )

    if not technology_cards:
        technology_cards.append(
            """
            <div class="empty">
                No technologies detected
            </div>
            """
        )

    # DNS
    dns_rows = []

    dns_data = result.dns or {}

    for address in dns_data.get("a", []):
        dns_rows.append(
            f"""
            <tr>
                <td>A</td>
                <td class="dns-value">
                    {_escape(address)}
                </td>
            </tr>
            """
        )

    for address in dns_data.get("aaaa", []):
        dns_rows.append(
            f"""
            <tr>
                <td>AAAA</td>
                <td class="dns-value">
                    {_escape(address)}
                </td>
            </tr>
            """
        )

    for ip_address, hostnames in dns_data.get(
        "ptr",
        {},
    ).items():
        for hostname in hostnames:
            dns_rows.append(
                f"""
                <tr>
                    <td>PTR</td>
                    <td class="dns-value">
                        {_escape(ip_address)}
                        &rarr;
                        {_escape(hostname)}
                    </td>
                </tr>
                """
            )

    if not dns_rows:
        dns_rows.append(
            """
            <tr>
                <td colspan="2" class="empty">
                    No DNS records detected
                </td>
            </tr>
            """
        )

    # Subdomains
    subdomain_rows = []

    for index, subdomain in enumerate(
        result.subdomains,
        start=1,
    ):
        subdomain_rows.append(
            f"""
            <tr>
                <td>{_escape(index)}</td>
                <td class="dns-value">
                    {_escape(subdomain)}
                </td>
            </tr>
            """
        )

    if not subdomain_rows:
        subdomain_rows.append(
            """
            <tr>
                <td colspan="2" class="empty">
                    No subdomains discovered
                </td>
            </tr>
            """
        )

    profile_text = (
        result.profile
        if result.profile
        else "Manual configuration"
    )

    html_document = f"""<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">

    <meta
        name="viewport"
        content="width=device-width, initial-scale=1.0"
    >

    <title>
        AtlasScan Report - {_escape(result.target)}
    </title>

    <style>
        :root {{
            --background: #0b1020;
            --surface: #121a2b;
            --surface-light: #19243a;
            --border: #263653;
            --text: #e8eefc;
            --muted: #8d9ab3;
            --accent: #54d6ff;
            --success: #44e38a;
        }}

        * {{
            box-sizing: border-box;
        }}

        body {{
            margin: 0;
            padding: 0;
            background: var(--background);
            color: var(--text);
            font-family:
                Inter,
                ui-sans-serif,
                system-ui,
                -apple-system,
                BlinkMacSystemFont,
                "Segoe UI",
                sans-serif;
        }}

        .container {{
            width: min(1400px, 94%);
            margin: 0 auto;
            padding: 40px 0 60px;
        }}

        .hero {{
            padding: 32px;
            border: 1px solid var(--border);
            border-radius: 18px;
            background:
                linear-gradient(
                    135deg,
                    #111a2e,
                    #0e1526
                );
            margin-bottom: 24px;
        }}

        .brand {{
            color: var(--accent);
            font-size: 14px;
            font-weight: 800;
            letter-spacing: 2px;
            text-transform: uppercase;
        }}

        h1 {{
            margin: 8px 0;
            font-size: clamp(30px, 5vw, 52px);
        }}

        .target {{
            color: var(--muted);
            font-size: 18px;
        }}

        .stats {{
            display: grid;
            grid-template-columns:
                repeat(
                    auto-fit,
                    minmax(180px, 1fr)
                );
            gap: 16px;
            margin-bottom: 24px;
        }}

        .stat {{
            padding: 22px;
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 14px;
        }}

        .stat-label {{
            color: var(--muted);
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}

        .stat-value {{
            margin-top: 8px;
            font-size: 28px;
            font-weight: 800;
        }}

        .section {{
            margin-top: 24px;
            padding: 24px;
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 16px;
            overflow-x: auto;
        }}

        h2 {{
            margin-top: 0;
            font-size: 21px;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            min-width: 700px;
        }}

        th,
        td {{
            padding: 13px 14px;
            border-bottom: 1px solid var(--border);
            text-align: left;
            vertical-align: top;
        }}

        th {{
            color: var(--muted);
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}

        .open {{
            color: var(--success);
            font-weight: 800;
        }}

        .banner {{
            max-width: 520px;
            white-space: pre-wrap;
            word-break: break-word;
            color: #c8d5ed;
            font-family:
                "JetBrains Mono",
                "Fira Code",
                monospace;
            font-size: 12px;
        }}

        .dns-value {{
            word-break: break-word;
            font-family:
                "JetBrains Mono",
                "Fira Code",
                monospace;
            font-size: 13px;
        }}

        .tech-grid {{
            display: grid;
            grid-template-columns:
                repeat(
                    auto-fit,
                    minmax(240px, 1fr)
                );
            gap: 14px;
        }}

        .tech-card {{
            padding: 18px;
            border: 1px solid var(--border);
            border-radius: 12px;
            background: var(--surface-light);
        }}

        .tech-name {{
            font-size: 17px;
            font-weight: 800;
            color: var(--accent);
        }}

        .tech-category,
        .tech-source,
        .tech-port {{
            margin-top: 8px;
            color: var(--muted);
            font-size: 13px;
        }}

        .empty {{
            color: var(--muted);
            text-align: center;
            padding: 24px;
        }}

        footer {{
            margin-top: 30px;
            color: var(--muted);
            text-align: center;
            font-size: 13px;
        }}
    </style>
</head>

<body>

    <main class="container">

        <section class="hero">
            <div class="brand">
                AtlasScan
            </div>

            <h1>
                Network Reconnaissance Report
            </h1>

            <div class="target">
                Target:
                <strong>
                    {_escape(result.target)}
                </strong>
            </div>
        </section>

        <section class="stats">

            <div class="stat">
                <div class="stat-label">
                    Open Ports
                </div>
                <div class="stat-value">
                    {_escape(result.open_port_count)}
                </div>
            </div>

            <div class="stat">
                <div class="stat-label">
                    Ports Scanned
                </div>
                <div class="stat-value">
                    {_escape(result.ports_scanned)}
                </div>
            </div>

            <div class="stat">
                <div class="stat-label">
                    Technologies
                </div>
                <div class="stat-value">
                    {_escape(result.technology_count)}
                </div>
            </div>

            <div class="stat">
                <div class="stat-label">
                    DNS Records
                </div>
                <div class="stat-value">
                    {_escape(result.dns_record_count)}
                </div>
            </div>

            <div class="stat">
                <div class="stat-label">
                    Subdomains
                </div>
                <div class="stat-value">
                    {_escape(result.subdomain_count)}
                </div>
            </div>

            <div class="stat">
                <div class="stat-label">
                    Duration
                </div>
                <div class="stat-value">
                    {_escape(
                        f"{result.duration_seconds:.2f}s"
                    )}
                </div>
            </div>

            <div class="stat">
                <div class="stat-label">
                    Profile
                </div>
                <div class="stat-value">
                    {_escape(profile_text)}
                </div>
            </div>

        </section>

        <section class="section">

            <h2>
                Open Ports
            </h2>

            <table>
                <thead>
                    <tr>
                        <th>Port</th>
                        <th>Status</th>
                        <th>Service</th>
                        <th>Version</th>
                        <th>Technologies</th>
                        <th>Banner</th>
                    </tr>
                </thead>

                <tbody>
                    {"".join(rows)}
                </tbody>
            </table>

        </section>

        <section class="section">

            <h2>
                HTTP Details
            </h2>

            <table>
                <thead>
                    <tr>
                        <th>Port</th>
                        <th>Status</th>
                        <th>Server</th>
                        <th>Content-Type</th>
                        <th>Content-Length</th>
                    </tr>
                </thead>

                <tbody>
                    {"".join(http_rows)}
                </tbody>
            </table>

        </section>

        <section class="section">

            <h2>
                DNS Records
            </h2>

            <table>
                <thead>
                    <tr>
                        <th>Type</th>
                        <th>Value</th>
                    </tr>
                </thead>

                <tbody>
                    {"".join(dns_rows)}
                </tbody>
            </table>

        </section>

        <section class="section">

            <h2>
                Discovered Subdomains
            </h2>

            <table>
                <thead>
                    <tr>
                        <th>#</th>
                        <th>Subdomain</th>
                    </tr>
                </thead>

                <tbody>
                    {"".join(subdomain_rows)}
                </tbody>
            </table>

        </section>

        <section class="section">

            <h2>
                Technology Fingerprints
            </h2>

            <div class="tech-grid">
                {"".join(technology_cards)}
            </div>

        </section>

        <footer>
            Generated by AtlasScan v1.0
            &bull;
            {_escape(result.timestamp)}
        </footer>

    </main>

</body>

</html>
"""

    output_path.write_text(
        html_document,
        encoding="utf-8",
    )
