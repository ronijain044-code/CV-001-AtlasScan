import re


def fingerprint_technology(
    service: str,
    version: str | None = None,
    banner: str | None = None,
    http_details: dict | None = None,
) -> list[dict[str, str]]:
    """
    Identify technologies from service, version, banner,
    and HTTP response metadata.
    """

    technologies: list[dict[str, str]] = []
    seen: set[str] = set()

    def add_technology(
        name: str,
        category: str,
        detected_from: str,
    ) -> None:
        key = name.lower()

        if key in seen:
            return

        seen.add(key)

        technologies.append(
            {
                "name": name,
                "category": category,
                "detected_from": detected_from,
            }
        )

    service_lower = (service or "").lower()
    version_text = version or ""
    banner_text = banner or ""

    combined = (
        f"{service_lower} "
        f"{version_text} "
        f"{banner_text}"
    )

    combined_lower = combined.lower()

    # SSH
    if "openssh" in combined_lower:
        match = re.search(
            r"openssh[_/\s-]*([0-9][\w.-]*)",
            combined,
            re.IGNORECASE,
        )

        name = "OpenSSH"

        if match:
            name = f"OpenSSH {match.group(1)}"

        add_technology(
            name,
            "remote-access",
            "banner",
        )

    # Apache
    if "apache" in combined_lower:
        match = re.search(
            r"apache/([0-9][\w.-]*)",
            combined,
            re.IGNORECASE,
        )

        name = "Apache"

        if match:
            name = f"Apache {match.group(1)}"

        add_technology(
            name,
            "web-server",
            "banner",
        )

    # Nginx
    if "nginx" in combined_lower:
        match = re.search(
            r"nginx/([0-9][\w.-]*)",
            combined,
            re.IGNORECASE,
        )

        name = "Nginx"

        if match:
            name = f"Nginx {match.group(1)}"

        add_technology(
            name,
            "web-server",
            "banner",
        )

    # Node.js / Express
    if "node.js" in combined_lower or "nodejs" in combined_lower:
        add_technology(
            "Node.js",
            "runtime",
            "banner",
        )

    if "express" in combined_lower:
        add_technology(
            "Express",
            "web-framework",
            "banner",
        )

    # PHP
    if re.search(r"\bphp\b", combined_lower):
        add_technology(
            "PHP",
            "runtime",
            "banner",
        )

    # Python
    if re.search(r"\bpython\b", combined_lower):
        add_technology(
            "Python",
            "runtime",
            "banner",
        )

    # Django
    if "django" in combined_lower:
        add_technology(
            "Django",
            "web-framework",
            "banner",
        )

    # WordPress
    if "wordpress" in combined_lower:
        add_technology(
            "WordPress",
            "cms",
            "banner",
        )

    # MySQL
    if "mysql" in combined_lower:
        add_technology(
            "MySQL",
            "database",
            "banner",
        )

    # PostgreSQL
    if "postgresql" in combined_lower:
        add_technology(
            "PostgreSQL",
            "database",
            "banner",
        )

    # Redis
    if "redis" in combined_lower:
        add_technology(
            "Redis",
            "database",
            "banner",
        )

    # HTTP metadata
    if http_details:
        server = str(
            http_details.get("server") or ""
        )

        content_type = str(
            http_details.get("content_type") or ""
        )

        allow = str(
            http_details.get("allow") or ""
        )

        http_combined = (
            f"{server} "
            f"{content_type} "
            f"{allow}"
        ).lower()

        if "apache" in http_combined:
            match = re.search(
                r"apache/([0-9][\w.-]*)",
                server,
                re.IGNORECASE,
            )

            name = "Apache"

            if match:
                name = f"Apache {match.group(1)}"

            add_technology(
                name,
                "web-server",
                "http-header",
            )

        if "nginx" in http_combined:
            match = re.search(
                r"nginx/([0-9][\w.-]*)",
                server,
                re.IGNORECASE,
            )

            name = "Nginx"

            if match:
                name = f"Nginx {match.group(1)}"

            add_technology(
                name,
                "web-server",
                "http-header",
            )

        if "php" in http_combined:
            add_technology(
                "PHP",
                "runtime",
                "http-header",
            )

        if "wordpress" in http_combined:
            add_technology(
                "WordPress",
                "cms",
                "http-header",
            )

    # Service-based fallback
    if service_lower == "ssh" and not any(
        item["category"] == "remote-access"
        for item in technologies
    ):
        add_technology(
            "SSH",
            "remote-access",
            "service",
        )

    if service_lower in {"http", "https"} and not any(
        item["category"] == "web-server"
        for item in technologies
    ):
        add_technology(
            "HTTP",
            "web",
            "service",
        )

    return technologies
