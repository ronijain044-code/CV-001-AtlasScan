from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from src.atlasscan.models import ScanResult


def _escape(value: Any) -> str:
    """
    Safely escape a value for HTML.
    """

    return html.escape(
        str(value)
    )


def _format_value(value: Any) -> str:
    """
    Format arbitrary values for human-readable HTML output.
    """

    if value is None:
        return "Unknown"

    if isinstance(value, bool):
        return "Yes" if value else "No"

    if isinstance(value, (dict, list)):
        return json.dumps(
            value,
            indent=2,
            ensure_ascii=False,
            default=str,
        )

    return str(value)


def _severity_class(
    severity: str,
) -> str:
    """
    Return a CSS class for a security severity.
    """

    normalized = str(
        severity
    ).lower()

    if normalized == "high":
        return "severity-high"

    if normalized == "medium":
        return "severity-medium"

    if normalized == "low":
        return "severity-low"

    return "severity-info"


def _grade_class(
    grade: str,
) -> str:
    """
    Return a CSS class for a security grade.
    """

    normalized = str(
        grade
    ).upper()

    if normalized == "A":
        return "grade-a"

    if normalized == "B":
        return "grade-b"

    if normalized == "C":
        return "grade-c"

    if normalized == "D":
        return "grade-d"

    return "grade-f"


def _render_stat(
    value: Any,
    label: str,
) -> str:
    """
    Render a dashboard statistic.
    """

    return f"""
<div class="stat">
    <div class="stat-value">
        {_escape(value)}
    </div>

    <div class="stat-label">
        {_escape(label)}
    </div>
</div>
"""


def _render_security_observations(
    result: ScanResult,
) -> str:
    """
    Render all security observations.
    """

    if not result.security:
        return """
<p class="muted">
    No security observations were generated.
</p>
"""

    rows: list[str] = []

    for port, details in sorted(
        result.security.items()
    ):
        observations = details.get(
            "observations",
            [],
        )

        if not isinstance(
            observations,
            list,
        ):
            continue

        for observation in observations:
            severity = str(
                observation.get(
                    "severity",
                    "unknown",
                )
            ).lower()

            rows.append(
                f"""
<tr>
    <td>{_escape(port)}</td>

    <td>
        <span class="{_severity_class(severity)}">
            {_escape(severity.upper())}
        </span>
    </td>

    <td>
        {_escape(
            observation.get(
                "title",
                "Unknown",
            )
        )}
    </td>

    <td>
        {_escape(
            observation.get(
                "description",
                "Unknown",
            )
        )}
    </td>

    <td>
        {_escape(
            observation.get(
                "evidence",
                "Unknown",
            )
        )}
    </td>
</tr>
"""
            )

    if not rows:
        return """
<p class="muted">
    No security observations were generated.
</p>
"""

    return f"""
<table>

<thead>
<tr>
    <th>Port</th>
    <th>Severity</th>
    <th>Finding</th>
    <th>Description</th>
    <th>Evidence</th>
</tr>
</thead>

<tbody>

{"".join(rows)}

</tbody>

</table>
"""


def generate_html_report(
    filename: str,
    result: ScanResult,
) -> None:
    """
    Generate a complete HTML report from a ScanResult.
    """

    output_path = Path(
        filename
    )

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    grade = result.security_grade
    risk_score = result.security_risk_score

    html_parts: list[str] = []

    html_parts.append(
        f"""<!DOCTYPE html>

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

* {{
    box-sizing: border-box;
}}

body {{
    margin: 0;
    padding: 0;

    background: #f4f7fb;

    color: #172033;

    font-family:
        -apple-system,
        BlinkMacSystemFont,
        "Segoe UI",
        sans-serif;

    line-height: 1.5;
}}

.container {{
    max-width: 1400px;

    margin: 0 auto;

    padding: 32px 24px 60px;
}}

.header {{
    background: #101828;

    color: white;

    border-radius: 16px;

    padding: 32px;

    margin-bottom: 24px;

    box-shadow:
        0 12px 30px
        rgba(16, 24, 40, 0.12);
}}

.header h1 {{
    margin: 0 0 8px;

    font-size: 32px;
}}

.header p {{
    margin: 4px 0;

    color: #d0d5dd;
}}

.section {{
    background: white;

    border-radius: 16px;

    padding: 24px;

    margin-bottom: 24px;

    box-shadow:
        0 8px 24px
        rgba(16, 24, 40, 0.06);

    overflow-x: auto;
}}

.section h2 {{
    margin-top: 0;

    margin-bottom: 20px;

    font-size: 22px;
}}

.stats {{
    display: grid;

    grid-template-columns:
        repeat(
            auto-fit,
            minmax(150px, 1fr)
        );

    gap: 16px;

    margin-bottom: 20px;
}}

.stat {{
    background: #f8fafc;

    border: 1px solid #e4e7ec;

    border-radius: 12px;

    padding: 18px;

    text-align: center;
}}

.stat-value {{
    font-size: 28px;

    font-weight: 700;

    color: #101828;
}}

.stat-label {{
    margin-top: 4px;

    color: #667085;

    font-size: 13px;

    text-transform: uppercase;

    letter-spacing: 0.05em;
}}

.security-assessment {{
    display: grid;

    grid-template-columns:
        minmax(180px, 1fr)
        minmax(180px, 1fr);

    gap: 20px;

    margin-bottom: 24px;
}}

.assessment-card {{
    border: 1px solid #e4e7ec;

    border-radius: 14px;

    padding: 24px;

    background: #f8fafc;

    text-align: center;
}}

.assessment-label {{
    color: #667085;

    font-size: 13px;

    text-transform: uppercase;

    letter-spacing: 0.05em;

    margin-bottom: 8px;
}}

.risk-score {{
    font-size: 42px;

    font-weight: 800;

    color: #101828;
}}

.grade {{
    display: inline-flex;

    align-items: center;

    justify-content: center;

    width: 74px;

    height: 74px;

    border-radius: 50%;

    font-size: 34px;

    font-weight: 800;

    color: white;
}}

.grade-a {{
    background: #12b76a;
}}

.grade-b {{
    background: #2e90fa;
}}

.grade-c {{
    background: #f79009;
}}

.grade-d {{
    background: #f04438;
}}

.grade-f {{
    background: #b42318;
}}

.severity-high {{
    color: #b42318;

    font-weight: 800;
}}

.severity-medium {{
    color: #b54708;

    font-weight: 800;
}}

.severity-low {{
    color: #344054;

    font-weight: 700;
}}

.severity-info {{
    color: #475467;

    font-weight: 600;
}}

.muted {{
    color: #667085;
}}

table {{
    width: 100%;

    border-collapse: collapse;

    min-width: 700px;
}}

th {{
    text-align: left;

    background: #f8fafc;

    color: #475467;

    font-size: 13px;

    text-transform: uppercase;

    letter-spacing: 0.04em;
}}

th,
td {{
    padding: 12px 14px;

    border-bottom:
        1px solid #eaecf0;

    vertical-align: top;
}}

tr:last-child td {{
    border-bottom: none;
}}

.code {{
    white-space: pre-wrap;

    word-break: break-word;

    background: #101828;

    color: #f2f4f7;

    border-radius: 8px;

    padding: 12px;

    font-family:
        "SFMono-Regular",
        Consolas,
        "Liberation Mono",
        monospace;

    font-size: 13px;
}}

.footer {{
    text-align: center;

    color: #667085;

    padding-top: 20px;

    font-size: 13px;
}}

@media (max-width: 700px) {{

    .container {{
        padding: 16px 12px 40px;
    }}

    .header {{
        padding: 24px;
    }}

    .header h1 {{
        font-size: 25px;
    }}

    .security-assessment {{
        grid-template-columns: 1fr;
    }}

}}

</style>

</head>

<body>

<div class="container">

<div class="header">

<h1>AtlasScan Report</h1>

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
    Ports scanned:
    <strong>{_escape(result.ports_scanned)}</strong>
</p>

<p>
    Open ports:
    <strong>{_escape(result.open_port_count)}</strong>
</p>

<p>
    Duration:
    <strong>
        {_escape(f"{result.duration_seconds:.2f}s")}
    </strong>
</p>

</div>
"""
    )

    # ---------------------------------------------------------
    # Scan Summary
    # ---------------------------------------------------------

    html_parts.append(
        """
<div class="section">

<h2>Scan Summary</h2>

<div class="stats">
"""
    )

    html_parts.append(
        _render_stat(
            result.open_port_count,
            "Open Ports",
        )
    )

    html_parts.append(
        _render_stat(
            result.technology_count,
            "Technologies",
        )
    )

    html_parts.append(
        _render_stat(
            result.dns_record_count,
            "DNS Records",
        )
    )

    html_parts.append(
        _render_stat(
            result.subdomain_count,
            "Subdomains",
        )
    )

    html_parts.append(
        _render_stat(
            result.web_count,
            "Web Inspections",
        )
    )

    html_parts.append(
        _render_stat(
            result.web_path_count,
            "Web Paths",
        )
    )

    html_parts.append(
        """
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

    for port in sorted(
        result.open_ports
    ):
        service_info = result.services.get(
            port,
            {},
        )

        service = service_info.get(
            "service",
            "unknown",
        )

        version = service_info.get(
            "version",
            "unknown",
        )

        technologies = result.technologies.get(
            port,
            [],
        )

        technology_names = []

        for technology in technologies:
            if isinstance(
                technology,
                dict,
            ):
                technology_names.append(
                    str(
                        technology.get(
                            "name",
                            "Unknown",
                        )
                    )
                )
            else:
                technology_names.append(
                    str(technology)
                )

        technology_text = (
            ", ".join(
                technology_names
            )
            if technology_names
            else "Unknown"
        )

        html_parts.append(
            f"""
<tr>

<td>{_escape(port)}</td>

<td>OPEN</td>

<td>{_escape(service)}</td>

<td>{_escape(version)}</td>

<td>{_escape(technology_text)}</td>

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
        details.get(
            "status_code",
            "Unknown",
        )
    )}
</td>

<td>
    {_escape(
        details.get(
            "server",
            "Unknown",
        )
    )}
</td>

<td>
    {_escape(
        details.get(
            "content_type",
            "Unknown",
        )
    )}
</td>

<td>
    {_escape(
        details.get(
            "content_length",
            "Unknown",
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
    # DNS Records
    # ---------------------------------------------------------

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

    dns_rendered = False

    if result.dns:

        for record_type, values in result.dns.items():

            if record_type == "ptr":

                if isinstance(
                    values,
                    dict,
                ):
                    for address, names in values.items():

                        if isinstance(
                            names,
                            list,
                        ):
                            for name in names:
                                dns_rendered = True

                                html_parts.append(
                                    f"""
<tr>
<td>PTR</td>
<td>
    {_escape(address)}
    →
    {_escape(name)}
</td>
</tr>
"""
                                )

                        elif names:
                            dns_rendered = True

                            html_parts.append(
                                f"""
<tr>
<td>PTR</td>
<td>
    {_escape(address)}
    →
    {_escape(names)}
</td>
</tr>
"""
                            )

                continue

            if isinstance(
                values,
                list,
            ):

                for value in values:
                    dns_rendered = True

                    html_parts.append(
                        f"""
<tr>
<td>{_escape(record_type.upper())}</td>
<td>{_escape(value)}</td>
</tr>
"""
                    )

            elif values:

                dns_rendered = True

                html_parts.append(
                    f"""
<tr>
<td>{_escape(record_type.upper())}</td>
<td>{_escape(values)}</td>
</tr>
"""
                )

    if not dns_rendered:
        html_parts.append(
            """
<tr>
<td colspan="2">
    No DNS records discovered
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

        for subdomain in sorted(
            result.subdomains
        ):
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
<p class="muted">
    No subdomains discovered
</p>
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

    if result.web:

        html_parts.append(
            """
<div class="section">

<h2>Web Inspection</h2>

<table>

<thead>
<tr>
    <th>Port</th>
    <th>Status</th>
    <th>Title</th>
    <th>Server</th>
    <th>Content-Type</th>
    <th>Redirect</th>
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
        details.get(
            "status_code",
            "Unknown",
        )
    )}
</td>

<td>
    {_escape(
        details.get(
            "title",
            "Unknown",
        )
    )}
</td>

<td>
    {_escape(
        details.get(
            "server",
            "Unknown",
        )
    )}
</td>

<td>
    {_escape(
        details.get(
            "content_type",
            "Unknown",
        )
    )}
</td>

<td>
    {_escape(
        "Yes"
        if details.get(
            "redirect",
            False,
        )
        else "No"
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
    # Security Assessment
    # ---------------------------------------------------------

    html_parts.append(
        f"""
<div class="section">

<h2>Security Assessment</h2>

<div class="security-assessment">

<div class="assessment-card">

<div class="assessment-label">
    Risk Score
</div>

<div class="risk-score">
    {_escape(risk_score)} / 100
</div>

</div>

<div class="assessment-card">

<div class="assessment-label">
    Security Grade
</div>

<div>
    <span class="grade {_grade_class(grade)}">
        {_escape(grade)}
    </span>
</div>

</div>

</div>

<div class="stats">

{_render_stat(
    result.security_observation_count,
    "Total Findings",
)}

{_render_stat(
    result.security_high_count,
    "High",
)}

{_render_stat(
    result.security_medium_count,
    "Medium",
)}

{_render_stat(
    result.security_low_count,
    "Low",
)}

</div>

</div>
"""
    )

    # ---------------------------------------------------------
    # Security Findings
    # ---------------------------------------------------------

    html_parts.append(
        """
<div class="section">

<h2>Security Findings</h2>

"""
    )

    html_parts.append(
        _render_security_observations(
            result
        )
    )

    html_parts.append(
        """
</div>
"""
    )

    # ---------------------------------------------------------
    # Robots.txt
    # ---------------------------------------------------------

    if result.robots:

        html_parts.append(
            """
<div class="section">

<h2>Robots.txt</h2>

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

            html_parts.append(
                f"""
<tr>

<td>{_escape(port)}</td>

<td>
    {_escape(
        details.get(
            "status_code",
            "Unknown",
        )
    )}
</td>

<td>
    {_escape(
        "Yes"
        if details.get(
            "exists",
            False,
        )
        else "No"
    )}
</td>

<td>
    {_escape(
        details.get(
            "url",
            "Unknown",
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
    # Web Paths
    # ---------------------------------------------------------

    if result.web_paths:

        html_parts.append(
            """
<div class="section">

<h2>Discovered Web Paths</h2>

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

        for port, paths in sorted(
            result.web_paths.items()
        ):

            if not isinstance(
                paths,
                list,
            ):
                continue

            for path_details in paths:

                html_parts.append(
                    f"""
<tr>

<td>{_escape(port)}</td>

<td>
    {_escape(
        path_details.get(
            "path",
            "Unknown",
        )
    )}
</td>

<td>
    {_escape(
        path_details.get(
            "status_code",
            "Unknown",
        )
    )}
</td>

<td>
    {_escape(
        path_details.get(
            "content_type",
            "Unknown",
        )
    )}
</td>

<td>
    {_escape(
        path_details.get(
            "content_length",
            "Unknown",
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
    # Service Banners
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

            banner_text = (
                banner
                if banner
                else "No banner"
            )

            html_parts.append(
                f"""
<tr>

<td>{_escape(port)}</td>

<td>
    <div class="code">
        {_escape(banner_text)}
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
