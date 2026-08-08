import socket


def inspect_http(
    host: str,
    port: int = 80,
    timeout: float = 2.0,
) -> dict[str, str | int | None]:
    """
    Collect basic HTTP response metadata.

    Args:
        host: Target hostname or IP address.
        port: HTTP service port.
        timeout: Connection timeout in seconds.

    Returns:
        Dictionary containing HTTP response metadata.
    """

    result: dict[str, str | int | None] = {
        "status_code": None,
        "server": None,
        "content_type": None,
        "content_length": None,
        "allow": None,
    }

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        sock.connect((host, port))

        request = (
            f"HEAD / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )

        sock.sendall(request.encode("ascii"))

        response = sock.recv(8192).decode(
            "utf-8",
            errors="replace",
        )

        lines = response.split("\r\n")

        if lines:
            status_line = lines[0].split()

            if len(status_line) >= 2:
                try:
                    result["status_code"] = int(status_line[1])
                except ValueError:
                    pass

        for line in lines[1:]:
            if ":" not in line:
                continue

            key, value = line.split(":", 1)

            key = key.strip().lower()
            value = value.strip()

            if key == "server":
                result["server"] = value

            elif key == "content-type":
                result["content_type"] = value

            elif key == "content-length":
                result["content_length"] = value

            elif key == "allow":
                result["allow"] = value

    except (socket.timeout, socket.error):
        pass

    finally:
        sock.close()

    return result
