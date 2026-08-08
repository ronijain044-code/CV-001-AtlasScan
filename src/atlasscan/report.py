from html import escape
from pathlib import Path


def generate_html_report(
    filename: str,
    target: str,
    ports_scanned: int,
    open_ports: list[int],
    services: dict[int, dict[str, str]],
    banners: dict[int, str | None],
    http_details: dict[int, dict[str, str | int | None]],
    technologies: dict[int, list[dict[str, str]]],
    duration: float,
) -> None:
    """
    Generate a standalone HTML reconnaissance report.
    """

    service_rows = []

    for port in open_ports:
        service_info = services.get(
            port,
            {
                "service": "unknown",
                "version": "unknown",
            },
        )

        service_rows.append(
            f"""
            <tr>
                <td>{escape(str(port))}</td>
                <td><span class="status">OPEN</span></td>
                <td>{escape(service_info["service"])}</td>
                <td>{escape(service_info["version"])}</td>
            </tr>
            """
        )

    technology_rows = []

    for port, tech_list in technologies.items():
        for technology in tech_list:
            technology_rows.append(
                f"""
                <tr>
                    <td>{escape(str(port))}</td>
                    <td>{escape(technology["name"])}</td>
                    <td>{escape(technology["category"])}</td>
                    <td>{escape(technology["detected_from"])}</td>
                </tr>
                """
            )

    http_rows = []

    for port, details in http_details.items():
        http_rows.append(
            f"""
            <tr>
                <td>{escape(str(port))}</td>
                <td>{escape(str(details.get("status_code") or "Unknown"))}</td>
                <td>{escape(str(details.get("server") or "Unknown"))}</td>
                <td>{escape(str(details.get("content_type") or "Unknown"))}</td>
                <td>{escape(str(details.get("content_length") or "Unknown"))}</td>
            </tr>
            """
        )

    banner_rows = []

    for port in open_ports:
        banner = banners.get(port)

        banner_rows.append(
            f"""
            <tr>
                <td>{escape(str(port))}</td>
                <td><pre>{escape(banner or "No banner")}</pre></td>
            </tr>
            """
        )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>AtlasScan Report - {escape(target)}</title>

    <style>
        :root {{
            color-scheme: dark;
        }}

        * {{
            box-sizing: border-box;
        }}

        body {{
            margin: 0;
            padding: 40px;
            background: #0b0f14;
            color: #e6edf3;
            font-family:
                -apple-system,
                BlinkMacSystemFont,
                "Segoe UI",
                sans-serif;
        }}

        .container {{
            max-width: 1200px;
            margin: auto;
        }}

        header {{
            padding: 32px;
            margin-bottom: 28px;
            border: 1px solid #30363d;
            border-radius: 14px;
            background: #111820;
        }}

        h1 {{
            margin: 0 0 8px;
            font-size: 34px;
        }}

        .subtitle {{
            color: #8b949e;
        }}

        .target {{
            margin-top: 20px;
            padding: 16px;
            border-radius: 10px;
            background: #0d1117;
            font-family: monospace;
            color: #58a6ff;
        }}

        .grid {{
            display: grid;
            grid-template-columns:
                repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin-bottom: 28px;
        }}

        .card {{
            padding: 22px;
            border: 1px solid #30363d;
            border-radius: 12px;
            background: #111820;
        }}

        .card-label {{
            color: #8b949e;
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 0.08em;
        }}

        .card-value {{
            margin-top: 8px;
            font-size: 28px;
            font-weight: 700;
        }}

        section {{
            margin-bottom: 28px;
            padding: 24px;
            border: 1px solid #30363d;
            border-radius: 14px;
            background: #111820;
        }}

        h2 {{
            margin-top: 0;
            font-size: 21px;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
        }}

        th,
        td {{
            padding: 12px;
            border-bottom: 1px solid #30363d;
            text-align: left;
            vertical-align: top;
        }}

        th {{
            color: #8b949e;
            font-size: 13px;
            text-transform: uppercase;
        }}

        .status {{
            color: #3fb950;
            font-weight: 700;
        }}

        pre {{
            margin: 0;
            white-space: pre-wrap;
            word-break: break-word;
            color: #8b949e;
            font-family: monospace;
        }}

        footer {{
            text-align: center;
            color: #6e7681;
            padding: 20px;
        }}

        @media (max-width: 700px) {{
            body {{
                padding: 18px;
            }}

            header {{
                padding: 22px;
            }}

            section {{
                padding: 18px;
            }}
        }}
    </style>
</head>

<body>

<div class="container">

    <header>
        <h1>AtlasScan</h1>

        <div class="subtitle">
            Network Reconnaissance Report
        </div>

        <div class="target">
            Target: {escape(target)}
        </div>
    </header>

    <div class="grid">

        <div class="card">
            <div class="card-label">
                Ports Scanned
            </div>
            <div class="card-value">
                {ports_scanned}
            </div>
        </div>

        <div class="card">
            <div class="card-label">
                Open Ports
            </div>
            <div class="card-value">
                {len(open_ports)}
            </div>
        </div>

        <div class="card">
            <div class="card-label">
                Services
            </div>
            <div class="card-value">
                {len(services)}
            </div>
        </div>

        <div class="card">
            <div class="card-label">
                Technologies
            </div>
            <div class="card-value">
                {sum(len(items) for items in technologies.values())}
            </div>
        </div>

        <div class="card">
            <div class="card-label">
                Duration
            </div>
            <div class="card-value">
                {duration:.2f}s
            </div>
        </div>

    </div>

    <section>
        <h2>Open Services</h2>

        <table>
            <thead>
                <tr>
                    <th>Port</th>
                    <th>Status</th>
                    <th>Service</th>
                    <th>Version</th>
                </tr>
            </thead>

            <tbody>
                {"".join(service_rows)}
            </tbody>
        </table>
    </section>

    <section>
        <h2>Technology Fingerprints</h2>

        <table>
            <thead>
                <tr>
                    <th>Port</th>
                    <th>Technology</th>
                    <th>Category</th>
                    <th>Detected From</th>
                </tr>
            </thead>

            <tbody>
                {"".join(technology_rows)}
            </tbody>
        </table>
    </section>

    <section>
        <h2>HTTP Intelligence</h2>

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

    <section>
        <h2>Service Banners</h2>

        <table>
            <thead>
                <tr>
                    <th>Port</th>
                    <th>Banner</th>
                </tr>
            </thead>

            <tbody>
                {"".join(banner_rows)}
            </tbody>
        </table>
    </section>

    <footer>
        Generated by AtlasScan
    </footer>

</div>

</body>
</html>
"""

    output_path = Path(filename)

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output_path.write_text(
        html,
        encoding="utf-8",
    )
