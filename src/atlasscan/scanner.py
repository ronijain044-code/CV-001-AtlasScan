import socket
from concurrent.futures import ThreadPoolExecutor


def scan_port(host: str, port: int, timeout: float = 1.0) -> bool:
    """
    Scan a single TCP port.

    Args:
        host: Target IP address or hostname.
        port: TCP port number.
        timeout: Connection timeout in seconds.

    Returns:
        True if the port is open, otherwise False.
    """

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        return sock.connect_ex((host, port)) == 0
    except (socket.timeout, socket.error):
        return False
    finally:
        sock.close()


def scan_ports(
    host: str,
    ports: list[int],
    timeout: float = 1.0,
    workers: int = 100,
) -> list[int]:
    """
    Scan multiple TCP ports concurrently.

    Args:
        host: Target IP address or hostname.
        ports: Ports to scan.
        timeout: Connection timeout in seconds.
        workers: Maximum number of concurrent workers.

    Returns:
        Sorted list of open ports.
    """

    workers = max(1, min(workers, len(ports))) if ports else 1

    with ThreadPoolExecutor(max_workers=workers) as executor:
        results = executor.map(
            lambda port: (port, scan_port(host, port, timeout)),
            ports,
        )

        open_ports = [
            port
            for port, is_open in results
            if is_open
        ]

    return sorted(open_ports)
