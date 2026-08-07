def parse_ports(port_string: str) -> list[int]:
    """
    Parse port input.

    Examples:
        1-100
        22
        22,80,443
        20-25,80,443
    """

    ports = set()

    for part in port_string.split(","):

        if "-" in part:
            start, end = part.split("-")
            ports.update(range(int(start), int(end) + 1))

        else:
            ports.add(int(part))

    return sorted(ports)
