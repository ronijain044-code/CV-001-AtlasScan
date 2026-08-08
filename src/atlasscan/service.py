import re


def identify_service(port: int, banner: str | None) -> dict[str, str]:
    """
    Identify a likely network service from the port and banner.

    Args:
        port: TCP port number.
        banner: Service banner returned by the target.

    Returns:
        Dictionary containing service and version information.
    """

    service = "unknown"
    version = "unknown"

    port_services = {
        21: "ftp",
        22: "ssh",
        23: "telnet",
        25: "smtp",
        53: "dns",
        80: "http",
        110: "pop3",
        143: "imap",
        443: "https",
        445: "smb",
        3306: "mysql",
        5432: "postgresql",
        6379: "redis",
        8080: "http",
    }

    service = port_services.get(port, "unknown")

    if not banner:
        return {
            "service": service,
            "version": version,
        }

    banner_lower = banner.lower()

    if "ssh-" in banner_lower:
        service = "ssh"

        match = re.search(
            r"openssh[_/\s-]*([0-9][\w.-]*)",
            banner,
            re.IGNORECASE,
        )

        if match:
            version = match.group(1)

    elif "apache" in banner_lower:
        service = "http"

        match = re.search(
            r"apache/([0-9][\w.-]*)",
            banner,
            re.IGNORECASE,
        )

        if match:
            version = match.group(1)

    elif "nginx" in banner_lower:
        service = "http"

        match = re.search(
            r"nginx/([0-9][\w.-]*)",
            banner,
            re.IGNORECASE,
        )

        if match:
            version = match.group(1)

    elif "http/" in banner_lower:
        service = "http"

    elif "mysql" in banner_lower:
        service = "mysql"

        match = re.search(
            r"mysql[\s/-]*([0-9][\w.-]*)",
            banner,
            re.IGNORECASE,
        )

        if match:
            version = match.group(1)

    elif "postgresql" in banner_lower:
        service = "postgresql"

    return {
        "service": service,
        "version": version,
    }
