# AtlasScan

AtlasScan is a professional network reconnaissance and security-assessment toolkit for authorized testing.

## Features

- TCP port scanning with configurable timeouts and concurrency
- DNS A, AAAA and PTR reconnaissance
- Subdomain discovery
- Service and banner detection
- Technology fingerprinting
- HTTP/web inspection
- Security-header analysis
- robots.txt and common-path discovery
- Potential vulnerability matching from a curated local database
- Unified security risk scoring
- JSON and HTML reports
- Quick, Standard and Thorough scan profiles

## Requirements

- Python 3.13+
- Linux, macOS or Windows with Python support
- Rich

## Installation

```bash
python -m pip install .
```

For development:

```bash
python -m pip install -e ".[dev]"
```

## Usage

Show help:

```bash
python -m src.atlasscan.cli --help
```

Quick scan:

```bash
python -m src.atlasscan.cli scanme.nmap.org --profile quick
```

Standard scan:

```bash
python -m src.atlasscan.cli scanme.nmap.org --profile standard
```

Thorough scan:

```bash
python -m src.atlasscan.cli scanme.nmap.org --profile thorough
```

Custom ports:

```bash
python -m src.atlasscan.cli example.com --ports 22,80,443
```

JSON report:

```bash
python -m src.atlasscan.cli example.com --profile quick --json report.json
```

HTML report:

```bash
python -m src.atlasscan.cli example.com --profile quick --html report.html
```

Both reports:

```bash
python -m src.atlasscan.cli example.com --profile quick --json report.json --html report.html
```

## Scan Profiles

| Profile | Ports | Timeout | Purpose |
|---|---:|---:|---|
| quick | 14 selected ports | 0.5s | Fast reconnaissance |
| standard | 1-1000 | 1.0s | General assessment |
| thorough | 1-10000 | 1.5s | Deeper port coverage |

## Testing

Run the complete test suite:

```bash
pytest -q
```

AtlasScan currently has 352 passing automated tests.

## Reports

AtlasScan can generate JSON reports for automation and HTML reports for human-readable assessment results.

Vulnerability matches represent potential exposure based on detected product/version ranges. They are not proof that a target is exploitable.

## Authorization

Only scan systems you own or have explicit permission to assess.

Do not use AtlasScan against unauthorized targets, networks or services.

## Project Status

AtlasScan v1.0.0
