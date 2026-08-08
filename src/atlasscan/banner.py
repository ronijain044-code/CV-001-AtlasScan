import socket


def grab_banner(
    host: str,
    port: int,
    timeout: float = 2.0,
) -> str | None:
    """
    Attempt to retrieve a service banner from an open TCP port.

    Args:
        host: Target IP address or hostname.
        port: Open TCP port.
        timeout: Connection timeout in seconds.

    Returns:
        Banner text if available, otherwise None.
    """

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        sock.connect((host, port))

        if port in {80, 8080, 8000, 8008}:
            request = (
                f"HEAD / HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )

            sock.sendall(request.encode("ascii"))

        data = sock.recv(4096)

        if not data:
            return None

        return data.decode("utf-8", errors="replace").strip()

    except (socket.timeout, socket.error, UnicodeError):
        return None

    finally:
        sock.close()
