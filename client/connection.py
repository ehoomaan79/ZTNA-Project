import socket
import ssl


TLS_TIMEOUT = 130


def connect_to_server(host: str, port: int, cafile: str) -> ssl.SSLSocket:
    context = ssl.create_default_context(cafile=cafile)

    raw_socket = socket.create_connection(
        (host, port),
        timeout=10,
    )

    connection = context.wrap_socket(
        raw_socket,
        server_hostname=host,
    )

    connection.settimeout(TLS_TIMEOUT)

    return connection


def connect_to_peer(host: str, port: int, local_port: int = 0) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        sock.bind(("0.0.0.0", local_port))
        sock.connect((host, port))
        return sock

    except Exception:
        sock.close()
        raise


def send_data(sock: socket.socket, data: bytes) -> None:
    sock.send(data)


def receive_data(sock: socket.socket, buffer_size: int = 65535) -> bytes:
    return sock.recv(buffer_size)


def close_connection(sock: socket.socket) -> None:
    try:
        sock.shutdown(socket.SHUT_RDWR)

    except OSError:
        pass

    finally:
        sock.close()