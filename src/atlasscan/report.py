from __future__ import annotations

import html
from pathlib import Path
from typing import Any

from src.atlasscan.models import ScanResult


def _escape(value: object) -> str:
    """Safely escape a value for HTML output."""
    return html.escape(str(value))


def _format_value(value: object) -> str:
    if value is None:
        return "Unknown"

    if value is True:
        return "Yes"

    if value is False:
        return "No"

    return str(value)


def _technology_names(
    technologies: list[dict[str, Any]],
) -> str:
    if not technologies:
        return "Unknown"

    names = []

    for technology in technologies:
        name = technology.get("name")

        if name:
            names.append(str(name))

    return ", ".join(names) if names else "Unknown"


def generate_html_report(
    filename: str,
    result: ScanResult | None = None,
    *,
    target: str | None = None,
    ports_scanned: int | None = None,
    open_ports: list[int] | None = None,
    services: dict[int, dict[str, Any]] | None = None,
    banners: dict[int, str | None] | None = None,
    http_details: dict[int, dict[str, Any]] | None = None,
    technologies: dict[int, list[dict[str, Any]]] | None = None,
    dns: dict[str, Any] | None = None,
    subdomains: list[str] | None = None,
    duration: float | None = None,
) -> None:
    """
    Generate a professional AtlasScan HTML report.

    Supports:
    - ScanResult-based API
    - Legacy keyword-based API
    - Port/service information
    - HTTP information
    - Technology fingerprints
    - DNS records
    - Subdomains
    - Web inspection
    - Security headers
    - robots.txt
    - Common web paths
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

    html_parts: list[str] = []

    html_parts.append(
        """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport"
      content="width=device-width, initial-scale=1.0">

<title>AtlasScan Report - %s</title>

<style>

* {
    box-sizing: border-box;
}

body {
    margin: 0;
    padding: 0;
    background: #f4f7fb;
    color: #172033;
    font-family:
        -apple-system,
        BlinkMacSystemFont,
        "Segoe UI",
        Roboto,
        Arial,
        sans-serif;
}

.container {
    width: min(1200px, 94%%);
    margin: 40px auto;
}

.header {
    background: #172033;
    color: white;
    padding: 32px;
    border-radius: 16px;
    margin-bottom: 24px;
}

.header h1 {
    margin: 0 0 8px 0;
    font-size: 32px;
}

.header p {
    margin: 4px 0;
    color: #c9d2e3;
}

.section {
    background: white;
    border-radius: 14px;
    padding: 24px;
    margin-bottom: 24px;
    box-shadow:
        0 4px 18px rgba(20, 30, 50, 0.07);
}

.section h2 {
    margin-top: 0;
    margin-bottom: 18px;
    font-size: 22px;
}

.stats {
    display: grid;
    grid-template-columns:
        repeat(auto-fit, minmax(150px, 1fr));
    gap: 14px;
}

.stat {
    background: #f5f7fb;
    border-radius: 12px;
    padding: 18px;
}

.stat-value {
    font-size: 28px;
    font-weight: 700;
}

.stat-label {
    color: #697386;
    margin-top: 4px;
}

table {
    width: 100%%;
    border-collapse: collapse;
    overflow: hidden;
}

th {
    background: #eef2f7;
    text-align: left;
    padding: 12px;
    font-size: 13px;
}

td {
    padding: 12px;
    border-bottom: 1px solid #e6eaf0;
    vertical-align: top;
}

tr:last-child td {
    border-bottom: none;
}

.badge {
    display: inline-block;
    padding: 4px 9px;
    border-radius: 999px;
    background: #e8f7ee;
    color: #187443;
    font-size: 12px;
    font-weight: 700;
}

.badge-muted {
    background: #eef1f5;
    color: #667085;
}

.code {
    white-space: pre-wrap;
    word-break: break-word;
    background: #101828;
    color: #e6edf5;
    padding: 14px;
    border-radius: 9px;
    font-family:
        "SFMono-Regular",
        Consolas,
        monospace;
    font-size: 12px;
}

.empty {
    color: #667085;
    padding: 12px 0;
}

.security-present {
    color: #187443;
    font-weight: 700;
}

.security-missing {
    color: #b42318;
    font-weight: 700;
}

.footer {
    text-align: center;
    color: #667085;
    padding: 20px;
    font-size: 13px;
}

@media (max-width: 700px) {

    .container {
        width: 94%%;
        margin: 20px auto;
    }

    .section {
        padding: 16px;
    }

    table {
        display: block;
        overflow-x: auto;
    }

}

</style>
</head>

<body>

<div class="container">
"""
        % _escape(result.target)
    )

    # ---------------------------------------------------------
    # Header
    # ---------------------------------------------------------

    html_parts.append(
        f"""
<div class="header">

    <h1>AtlasScan</h1>

    <p>
        Professional Network Reconnaissance Report
    </p>

    <p>
        Target:
        <strong>{_escape(result.target)}</strong>
    </p>

    <p>
        Profile:
        <strong>
            {_escape(result.profile or "Manual configuration")}
        </strong>
    </p>

    <p>
        Generated:
        {_escape(result.timestamp)}
    </p>

</div>
"""
    )

    # ---------------------------------------------------------
    # Summary
    # ---------------------------------------------------------

    html_parts.append(
        f"""
<div class="section">

    <h2>Scan Summary</h2>

    <div class="stats">

        <div class="stat">
            <div class="stat-value">
                {result.ports_scanned}
            </div>
            <div class="stat-label">
                Ports Scanned
            </div>
        </div>

        <div class="stat">
            <div class="stat-value">
                {result.open_port_count}
            </div>
            <div class="stat-label">
                Open Ports
            </div>
        </div>

        <div class="stat">
            <div class="stat-value">
                {result.technology_count}
            </div>
            <div class="stat-label">
                Technologies
            </div>
        </div>

        <div class="stat">
            <div class="stat-value">
                {result.dns_record_count}
            </div>
            <div class="stat-label">
                DNS Records
            </div>
        </div>

        <div class="stat">
            <div class="stat-value">
                {result.subdomain_count}
            </div>
            <div class="stat-label">
                Subdomains
            </div>
        </div>

        <div class="stat">
            <div class="stat-value">
                {result.web_count}
            </div>
            <div class="stat-label">
                Web Inspections
            </div>
        </div>

        <div class="stat">
            <div class="stat-value">
                {result.web_path_count}
            </div>
            <div class="stat-label">
                Web Paths
            </div>
        </div>

        <div class="stat">
            <div class="stat-value">
                {_escape(f"{result.duration_seconds:.2f}s")}
            </div>
            <div class="stat-label">
                Duration
            </div>
        </div>

    </div>

</div>
"""
    )

    # ---------------------------------------------------------
    # Open Ports
    # ---------------------------------------------------------

    html_parts.append(
        """
<div class="section">

<h2>Open Ports</h2>
"""
    )

    if result.open_ports:

        html_parts.append(
            """
<table>

<thead>
<tr>
    <th>Port</th>
    <th>Status</th>
    <th>Service</th>
    <th>Version</th>
    <th>Technologies</th>
</tr>
</thead>

<tbody>
"""
        )

        for port in result.open_ports:

            service = result.services.get(
                port,
                {},
            )

            technology_list = result.technologies.get(
                port,
                [],
            )

            html_parts.append(
                f"""
<tr>

<td>
    <strong>{_escape(port)}</strong>
</td>

<td>
    <span class="badge">
        OPEN
    </span>
</td>

<td>
    {_escape(service.get("service", "unknown"))}
</td>

<td>
    {_escape(service.get("version", "unknown"))}
</td>

<td>
    {_escape(
        _technology_names(technology_list)
    )}
</td>

</tr>
"""
            )

        html_parts.append(
            """
</tbody>
</table>
"""
        )

    else:

        html_parts.append(
            """
<div class="empty">
    No open ports discovered.
</div>
"""
        )

    html_parts.append(
        """
</div>
"""
    )

    # ---------------------------------------------------------
    # HTTP Details
    # ---------------------------------------------------------

    if result.http:

        html_parts.append(
            """
<div class="section">

<h2>HTTP Details</h2>

<table>

<thead>
<tr>
    <th>Port</th>
    <th>Status</th>
    <th>Server</th>
    <th>Content-Type</th>
    <th>Content-Length</th>
    <th>Allow</th>
</tr>
</thead>

<tbody>
"""
        )

        for port, details in sorted(
            result.http.items()
        ):

            html_parts.append(
                f"""
<tr>

<td>{_escape(port)}</td>

<td>
    {_escape(
        _format_value(
            details.get("status_code")
        )
    )}
</td>

<td>
    {_escape(
        _format_value(
            details.get("server")
        )
    )}
</td>

<td>
    {_escape(
        _format_value(
            details.get("content_type")
        )
    )}
</td>

<td>
    {_escape(
        _format_value(
            details.get("content_length")
        )
    )}
</td>

<td>
    {_escape(
        _format_value(
            details.get("allow")
        )
    )}
</td>

</tr>
"""
            )

        html_parts.append(
            """
</tbody>
</table>
</div>
"""
        )

    # ---------------------------------------------------------
    # DNS
    # ---------------------------------------------------------

    if result.dns:

        html_parts.append(
            """
<div class="section">

<h2>DNS Records</h2>

<table>

<thead>
<tr>
    <th>Type</th>
    <th>Value</th>
</tr>
</thead>

<tbody>
"""
        )

        a_records = result.dns.get(
            "a",
            [],
        )

        for value in a_records:
            html_parts.append(
                f"""
<tr>
    <td><strong>A</strong></td>
    <td>{_escape(value)}</td>
</tr>
"""
            )

        aaaa_records = result.dns.get(
            "aaaa",
            [],
        )

        for value in aaaa_records:
            html_parts.append(
                f"""
<tr>
    <td><strong>AAAA</strong></td>
    <td>{_escape(value)}</td>
</tr>
"""
            )

        ptr_records = result.dns.get(
            "ptr",
            {},
        )

        if isinstance(ptr_records, dict):

            for address, names in ptr_records.items():

                if isinstance(names, list):
                    for name in names:
                        html_parts.append(
                            f"""
<tr>
    <td><strong>PTR</strong></td>
    <td>
        {_escape(address)}
        →
        {_escape(name)}
    </td>
</tr>
"""
                        )

                else:
                    html_parts.append(
                        f"""
<tr>
    <td><strong>PTR</strong></td>
    <td>
        {_escape(address)}
        →
        {_escape(names)}
    </td>
</tr>
"""
                    )

        html_parts.append(
            """
</tbody>
</table>
</div>
"""
        )

    # ---------------------------------------------------------
    # Subdomains
    # ---------------------------------------------------------

    html_parts.append(
        """
<div class="section">

<h2>Discovered Subdomains</h2>
"""
    )

    if result.subdomains:

        html_parts.append(
            """
<table>

<thead>
<tr>
    <th>Subdomain</th>
</tr>
</thead>

<tbody>
"""
        )

        for subdomain in result.subdomains:

            html_parts.append(
                f"""
<tr>
    <td>{_escape(subdomain)}</td>
</tr>
"""
            )

        html_parts.append(
            """
</tbody>
</table>
"""
        )

    else:

        html_parts.append(
            """
<div class="empty">
    No subdomains discovered.
</div>
"""
        )

    html_parts.append(
        """
</div>
"""
    )

    # ---------------------------------------------------------
    # Web Inspection
    # ---------------------------------------------------------

    html_parts.append(
        """
<div class="section">

<h2>Web Inspection</h2>
"""
    )

    if result.web:

        html_parts.append(
            """
<table>

<thead>
<tr>
    <th>Port</th>
    <th>Status</th>
    <th>Title</th>
    <th>Server</th>
    <th>Content-Type</th>
    <th>Redirect</th>
    <th>Final URL</th>
</tr>
</thead>

<tbody>
"""
        )

        for port, details in sorted(
            result.web.items()
        ):

            html_parts.append(
                f"""
<tr>

<td>{_escape(port)}</td>

<td>
    {_escape(
        _format_value(
            details.get("status_code")
        )
    )}
</td>

<td>
    {_escape(
        _format_value(
            details.get("title")
        )
    )}
</td>

<td>
    {_escape(
        _format_value(
            details.get("server")
        )
    )}
</td>

<td>
    {_escape(
        _format_value(
            details.get("content_type")
        )
    )}
</td>

<td>
    {_escape(
        _format_value(
            details.get("redirect")
        )
    )}
</td>

<td>
    {_escape(
        _format_value(
            details.get("final_url")
        )
    )}
</td>

</tr>
"""
            )

        html_parts.append(
            """
</tbody>
</table>
"""
        )

    else:

        html_parts.append(
            """
<div class="empty">
    No web inspection results.
</div>
"""
        )

    html_parts.append(
        """
</div>
"""
    )

    # ---------------------------------------------------------
    # Security Headers
    # ---------------------------------------------------------

    if result.web:

        html_parts.append(
            """
<div class="section">

<h2>Security Headers</h2>

<table>

<thead>
<tr>
    <th>Port</th>
    <th>Header</th>
    <th>Status</th>
    <th>Value</th>
</tr>
</thead>

<tbody>
"""
        )

        for port, details in sorted(
            result.web.items()
        ):

            security_headers = details.get(
                "security_headers",
                {},
            )

            if not security_headers:
                html_parts.append(
                    f"""
<tr>
    <td>{_escape(port)}</td>
    <td colspan="3">
        No security header data available.
    </td>
</tr>
"""
                )
                continue

            for header, value in security_headers.items():

                present = value is not None

                status = (
                    "Present"
                    if present
                    else "Missing"
                )

                css_class = (
                    "security-present"
                    if present
                    else "security-missing"
                )

                html_parts.append(
                    f"""
<tr>

<td>{_escape(port)}</td>

<td>
    {_escape(header)}
</td>

<td class="{css_class}">
    {_escape(status)}
</td>

<td>
    {_escape(
        _format_value(value)
    )}
</td>

</tr>
"""
                )

        html_parts.append(
            """
</tbody>
</table>
</div>
"""
        )

    # ---------------------------------------------------------
    # Security Findings
    # ---------------------------------------------------------

    html_parts.append(
        f"""
<div class="section">

<h2>Security Findings</h2>

<div class="stats">

    <div class="stat">
        <div class="stat-value">
            {result.security_observation_count}
        </div>
        <div class="stat-label">
            Total Findings
        </div>
    </div>

    <div class="stat">
        <div class="stat-value">
            {result.security_high_count}
        </div>
        <div class="stat-label">
            High
        </div>
    </div>

    <div class="stat">
        <div class="stat-value">
            {result.security_medium_count}
        </div>
        <div class="stat-label">
            Medium
        </div>
    </div>

    <div class="stat">
        <div class="stat-value">
            {result.security_low_count}
        </div>
        <div class="stat-label">
            Low
        </div>
    </div>

</div>
"""
    )

    if result.security:
        html_parts.append(
            """
<table>

<thead>
<tr>
    <th>Port</th>
    <th>Severity</th>
    <th>Title</th>
    <th>Description</th>
    <th>Evidence</th>
</tr>
</thead>

<tbody>
"""
        )

        for port, details in sorted(result.security.items()):
            observations = details.get("observations", [])

            if not isinstance(observations, list):
                continue

            for observation in observations:
                severity = str(
                    observation.get("severity", "unknown")
                ).lower()

                html_parts.append(
                    f"""
<tr>

<td>{_escape(port)}</td>

<td>
    <strong>{_escape(severity.upper())}</strong>
</td>

<td>
    {_escape(observation.get("title", "Unknown"))}
</td>

<td>
    {_escape(observation.get("description", "Unknown"))}
</td>

<td>
    {_escape(observation.get("evidence", "Unknown"))}
</td>

</tr>
"""
                )

        html_parts.append(
            """
</tbody>
</table>
"""
        )
    else:
        html_parts.append(
            """
<div class="empty">
    No security observations recorded.
</div>
"""
        )

    html_parts.append(
        """
</div>
"""
    )

    # ---------------------------------------------------------
    # Robots.txt
    # ---------------------------------------------------------

    html_parts.append(
        """
<div class="section">

<h2>Robots.txt</h2>
"""
    )

    if result.robots:

        html_parts.append(
            """
<table>

<thead>
<tr>
    <th>Port</th>
    <th>Status</th>
    <th>Exists</th>
    <th>URL</th>
</tr>
</thead>

<tbody>
"""
        )

        for port, details in sorted(
            result.robots.items()
        ):

            exists = bool(
                details.get("exists")
            )

            html_parts.append(
                f"""
<tr>

<td>{_escape(port)}</td>

<td>
    {_escape(
        _format_value(
            details.get("status_code")
        )
    )}
</td>

<td>
    <span class="badge{
        "" if exists else " badge-muted"
    }">
        {"Yes" if exists else "No"}
    </span>
</td>

<td>
    {_escape(
        _format_value(
            details.get("url")
        )
    )}
</td>

</tr>
"""
            )

        html_parts.append(
            """
</tbody>
</table>
"""
        )

        for port, details in sorted(
            result.robots.items()
        ):

            content = details.get(
                "content"
            )

            if content:

                html_parts.append(
                    f"""
<h3>
    robots.txt content — port {_escape(port)}
</h3>

<div class="code">
{_escape(content)}
</div>
"""
                )

    else:

        html_parts.append(
            """
<div class="empty">
    No robots.txt results.
</div>
"""
        )

    html_parts.append(
        """
</div>
"""
    )

    # ---------------------------------------------------------
    # Web Paths
    # ---------------------------------------------------------

    html_parts.append(
        """
<div class="section">

<h2>Discovered Web Paths</h2>
"""
    )

    if result.web_paths:

        html_parts.append(
            """
<table>

<thead>
<tr>
    <th>Port</th>
    <th>Path</th>
    <th>Status</th>
    <th>Content-Type</th>
    <th>Content-Length</th>
</tr>
</thead>

<tbody>
"""
        )

        found_paths = False

        for port, paths in sorted(
            result.web_paths.items()
        ):

            for path_info in paths:

                found_paths = True

                html_parts.append(
                    f"""
<tr>

<td>{_escape(port)}</td>

<td>
    {_escape(
        _format_value(
            path_info.get("path")
        )
    )}
</td>

<td>
    {_escape(
        _format_value(
            path_info.get("status_code")
        )
    )}
</td>

<td>
    {_escape(
        _format_value(
            path_info.get("content_type")
        )
    )}
</td>

<td>
    {_escape(
        _format_value(
            path_info.get("content_length")
        )
    )}
</td>

</tr>
"""
                )

        if not found_paths:

            html_parts.append(
                """
<tr>
    <td colspan="5">
        No web paths discovered.
    </td>
</tr>
"""
            )

        html_parts.append(
            """
</tbody>
</table>
"""
        )

    else:

        html_parts.append(
            """
<div class="empty">
    No web paths discovered.
</div>
"""
        )

    html_parts.append(
        """
</div>
"""
    )

    # ---------------------------------------------------------
    # Banners
    # ---------------------------------------------------------

    if result.banners:

        html_parts.append(
            """
<div class="section">

<h2>Service Banners</h2>

<table>

<thead>
<tr>
    <th>Port</th>
    <th>Banner</th>
</tr>
</thead>

<tbody>
"""
        )

        for port, banner in sorted(
            result.banners.items()
        ):

            if not banner:
                banner = "No banner"

            html_parts.append(
                f"""
<tr>

<td>{_escape(port)}</td>

<td>
    <div class="code">
        {_escape(banner)}
    </div>
</td>

</tr>
"""
            )

        html_parts.append(
            """
</tbody>
</table>
</div>
"""
        )

    # ---------------------------------------------------------
    # Footer
    # ---------------------------------------------------------

    html_parts.append(
        """
<div class="footer">
    Generated by AtlasScan
</div>

</div>

</body>
</html>
"""
    )

    output_path.write_text(
        "".join(html_parts),
        encoding="utf-8",
    )