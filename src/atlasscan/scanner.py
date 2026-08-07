import socket
from concurrent.futures import ThreadPoolExecutor


def scan_port(host: str, port: int, timeout: float = 1.0) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        return sock.connect_ex((host, port)) == 0
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
    Returns a list of open ports.
    """

    open_ports = []

    def worker(port: int):
        if scan_port(host, port, timeout):
            open_ports.append(port)

    with ThreadPoolExecutor(max_workers=workers) as executor:
        executor.map(worker, ports)

    return sorted(open_ports)
