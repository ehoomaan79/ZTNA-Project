import socket
import time


def register_endpoint(
    client_id: str,
    public_ip: str,
    public_port: int,
) -> dict:
    if not client_id:
        raise ValueError("Client ID is required")

    if not public_ip:
        raise ValueError("Public IP is required")

    if not 1 <= public_port <= 65535:
        raise ValueError("Invalid public port")

    return {
        "client_id": client_id,
        "public_ip": public_ip,
        "public_port": public_port,
    }


def exchange_endpoints(
    endpoint_a: dict,
    endpoint_b: dict,
) -> tuple[dict, dict]:
    if not endpoint_a or not endpoint_b:
        raise ValueError(
            "Both endpoints are required"
        )

    return (
        endpoint_a.copy(),
        endpoint_b.copy(),
    )


def perform_nat_traversal(
    sock: socket.socket,
    remote_endpoint: tuple[str, int],
    client_id: str,
    attempts: int = 20,
    interval: float = 0.5,
) -> bool:
    if not client_id:
        raise ValueError(
            "Client ID is required"
        )

    probe = (
        f"NAT_PROBE:{client_id}:{time.time()}"
    ).encode()

    sock.settimeout(interval)

    for _ in range(attempts):
        try:
            sock.send(probe)

            data = sock.recv(4096)

            if data.startswith(b"NAT_PROBE:"):
                sock.send(b"NAT_ACK")
                return True

            if data == b"NAT_ACK":
                return True

        except socket.timeout:
            continue

    return False