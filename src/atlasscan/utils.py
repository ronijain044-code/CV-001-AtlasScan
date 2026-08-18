import ipaddress
import re

def parse_ports(port_string: str) -> list[int]:
    """
    Parse and validate port input.

    Examples:
        1-100
        22
        22,80,443
        20-25,80,443

    Raises:
        ValueError: If the port specification is invalid.
    """
    if not isinstance(port_string, str):
        raise ValueError("Port specification must be a string")

    port_string = port_string.strip()

    if not port_string:
        raise ValueError("Port specification cannot be empty")

    ports: set[int] = set()

    for part in port_string.split(","):
        part = part.strip()

        if not part:
            raise ValueError(
                "Invalid port specification: empty value"
            )

        if "-" in part:
            pieces = part.split("-")

            if len(pieces) != 2:
                raise ValueError(
                    f"Invalid port range: '{part}'"
                )

            start_text, end_text = (
                piece.strip()
                for piece in pieces
            )

            if not start_text or not end_text:
                raise ValueError(
                    f"Invalid port range: '{part}'"
                )

            try:
                start = int(start_text)
                end = int(end_text)
            except ValueError as exc:
                raise ValueError(
                    f"Invalid port range: '{part}'"
                ) from exc

            if start < 1 or end > 65535:
                raise ValueError(
                    f"Port must be between 1 and 65535: '{part}'"
                )

            if start > end:
                raise ValueError(
                    f"Invalid port range: '{part}'"
                )

            ports.update(
                range(start, end + 1)
            )

        else:
            try:
                port = int(part)
            except ValueError as exc:
                raise ValueError(
                    f"Invalid port: '{part}'"
                ) from exc

            if port < 1 or port > 65535:
                raise ValueError(
                    f"Port must be between 1 and 65535: '{port}'"
                )

            ports.add(port)

    if not ports:
        raise ValueError(
            "Port specification produced no ports"
        )

    return sorted(ports)


def validate_target(target: str) -> str:
    """
    Validate and normalize an IP address or hostname.

    Raises:
        ValueError: If the target is invalid.
    """
    if not isinstance(target, str):
        raise ValueError("Target must be a string")

    target = target.strip()

    if not target:
        raise ValueError("Target cannot be empty")

    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass

    # Reject malformed IPv4-looking targets instead of treating
    # them as hostnames, e.g. 999.999.999.999 or 192.168.1.
    if re.fullmatch(r"\d+(?:\.\d+)+", target):
        raise ValueError(
            f"Invalid IP address: '{target}'"
        )

    if len(target) > 253:
        raise ValueError("Target hostname is too long")

    hostname = target.rstrip(".")

    hostname_pattern = re.compile(
        r"^(?=.{1,253}$)"
        r"(?:[A-Za-z0-9]"
        r"(?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
        r"\.)*"
        r"[A-Za-z0-9]"
        r"(?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
    )

    if not hostname_pattern.fullmatch(hostname):
        raise ValueError(f"Invalid target: '{target}'")

    return target
