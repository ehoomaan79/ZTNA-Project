import socket
import ssl
import threading
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from common.protocol import (
    AUTH,
    AUTH_RESPONSE,
    TOKEN,
    KEY_EXCHANGE,
    PEER_REQUEST,
    ENDPOINT_INFO,
    decode_bytes,
    create_message,
    receive_message,
)

from server.authorization import (
    authenticate_client,
    check_access,
    create_password_hash,
    create_token,
    validate_token,
)

from server.session import manage_session


SERVER_HOST = "0.0.0.0"
TLS_PORT = 8443
UDP_PORT = 8444

PEER_WAIT_TIMEOUT = 120

BASE_DIR = Path(__file__).resolve().parent
CERT_DIR = BASE_DIR / "certs"
CERT_FILE = CERT_DIR / "server.crt"
KEY_FILE = CERT_DIR / "server.key"

clients = {}
clients_lock = threading.Lock()
clients_condition = threading.Condition(clients_lock)

ACCESS_LIST = {
    ("client1", "client2"),
    ("client2", "client1"),
}


def get_server_addresses():
    addresses = set()

    try:
        hostname = socket.gethostname()

        for address in socket.gethostbyname_ex(hostname)[2]:
            addresses.add(address)
    except socket.gaierror:
        pass

    try:
        probe = socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM,
        )
        probe.connect(("8.8.8.8", 80))
        addresses.add(probe.getsockname()[0])
        probe.close()
    except OSError:
        pass

    addresses.add("127.0.0.1")

    return addresses


def generate_certificate():
    CERT_DIR.mkdir(parents=True, exist_ok=True)

    if CERT_FILE.exists() and KEY_FILE.exists():
        return

    print("Generating self-signed TLS certificate...")

    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    subject = issuer = x509.Name(
        [
            x509.NameAttribute(
                NameOID.COMMON_NAME,
                "ZTNA Server",
            )
        ]
    )

    san_names = [
        x509.DNSName("localhost"),
    ]

    for address in get_server_addresses():
        try:
            san_names.append(
                x509.IPAddress(ip_address(address))
            )
        except ValueError:
            pass

    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(
            datetime.now(timezone.utc)
            - timedelta(minutes=1)
        )
        .not_valid_after(
            datetime.now(timezone.utc)
            + timedelta(days=3650)
        )
        .add_extension(
            x509.SubjectAlternativeName(san_names),
            critical=False,
        )
        .sign(
            key,
            hashes.SHA256(),
        )
    )

    KEY_FILE.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    CERT_FILE.write_bytes(
        certificate.public_bytes(
            serialization.Encoding.PEM
        )
    )

    print(f"Certificate created: {CERT_FILE}")
    print(f"Private key created: {KEY_FILE}")


def send_endpoint_info(connection, endpoint):
    connection.sendall(
        create_message(
            ENDPOINT_INFO,
            client_id=endpoint["client_id"],
            public_ip=endpoint["public_ip"],
            public_port=endpoint["public_port"],
            public_key=endpoint["public_key"],
        )
    )


def wait_for_peer(client_id, peer_id):
    deadline = datetime.now().timestamp() + PEER_WAIT_TIMEOUT

    with clients_condition:
        while True:
            client = clients.get(client_id)
            peer = clients.get(peer_id)

            if not client:
                return None, None

            if peer:
                client_endpoint = client.get("endpoint")
                peer_endpoint = peer.get("endpoint")

                if client_endpoint and peer_endpoint:
                    return client, peer

            remaining = deadline - datetime.now().timestamp()

            if remaining <= 0:
                return None, None

            clients_condition.wait(timeout=remaining)


def handle_peer_request(client_id, connection, message):
    token = message["token"]
    peer_id = message["peer_id"]

    session = manage_session(
        client_id,
        "",
        0,
        "get",
    )

    if not validate_token(
        client_id,
        token,
        session,
    ):
        connection.sendall(
            create_message(
                AUTH_RESPONSE,
                status="deny",
                message="Invalid or expired token",
            )
        )
        return

    if not check_access(
        client_id,
        peer_id,
        ACCESS_LIST,
    ):
        connection.sendall(
            create_message(
                AUTH_RESPONSE,
                status="deny",
                message="Access denied",
            )
        )
        return

    print(
        f"Peer request: {client_id} -> {peer_id}. "
        f"Waiting for peer..."
    )

    client, peer = wait_for_peer(
        client_id,
        peer_id,
    )

    if not client or not peer:
        connection.sendall(
            create_message(
                AUTH_RESPONSE,
                status="deny",
                message="Peer connection timed out",
            )
        )
        return

    print(
        f"Peer ready: {client_id} <-> {peer_id}"
    )

    send_endpoint_info(
        client["connection"],
        peer["endpoint"],
    )

    send_endpoint_info(
        peer["connection"],
        client["endpoint"],
    )


def handle_client(connection, users):
    client_id = None

    try:
        message = receive_message(connection)

        if message["type"] != AUTH:
            connection.sendall(
                create_message(
                    AUTH_RESPONSE,
                    status="deny",
                    message="Authentication required",
                )
            )
            return

        username = message["username"]
        password = message["password"]

        if not authenticate_client(
            username,
            password,
            users,
        ):
            connection.sendall(
                create_message(
                    AUTH_RESPONSE,
                    status="deny",
                    message="Invalid credentials",
                )
            )
            return

        client_id = username

        token, expires_at = create_token(
            client_id
        )

        manage_session(
            client_id,
            token,
            expires_at,
            "create",
        )

        with clients_condition:
            clients[client_id] = {
                "connection": connection,
                "endpoint": None,
                "public_key": None,
            }

            clients_condition.notify_all()

        connection.sendall(
            create_message(
                AUTH_RESPONSE,
                status="allow",
                message="Authentication successful",
            )
        )

        connection.sendall(
            create_message(
                TOKEN,
                token=token,
                expires_at=expires_at,
            )
        )

        while True:
            message = receive_message(connection)

            if message["type"] == KEY_EXCHANGE:
                public_key = decode_bytes(
                    message["public_key"]
                )

                if len(public_key) != 32:
                    raise ValueError(
                        "Invalid public key"
                    )

                with clients_condition:
                    if client_id in clients:
                        clients[client_id][
                            "public_key"
                        ] = message["public_key"]

                        clients_condition.notify_all()

            elif message["type"] == PEER_REQUEST:
                handle_peer_request(
                    client_id,
                    connection,
                    message,
                )

            else:
                connection.sendall(
                    create_message(
                        AUTH_RESPONSE,
                        status="deny",
                        message="Unexpected message",
                    )
                )

    except (
        ConnectionError,
        OSError,
        ValueError,
    ):
        pass

    finally:
        if client_id:
            with clients_condition:
                clients.pop(client_id, None)
                clients_condition.notify_all()

            manage_session(
                client_id,
                "",
                0,
                "remove",
            )

        try:
            connection.close()
        except OSError:
            pass


def udp_endpoint_listener(host, port):
    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM,
    )

    sock.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1,
    )

    sock.bind((host, port))

    print(
        f"ZTNA UDP listener on "
        f"{host}:{port}"
    )

    while True:
        data, address = sock.recvfrom(4096)

        if not data.startswith(b"NAT_PROBE:"):
            continue

        try:
            parts = data.decode().split(":", 2)
            client_id = parts[1]
        except (
            UnicodeDecodeError,
            IndexError,
        ):
            continue

        with clients_condition:
            client = clients.get(client_id)

            if not client:
                continue

            if not client.get("public_key"):
                continue

            client["endpoint"] = {
                "client_id": client_id,
                "public_ip": address[0],
                "public_port": address[1],
                "public_key": client["public_key"],
            }

            clients_condition.notify_all()

        sock.sendto(
            b"NAT_ACK",
            address,
        )


def main():
    users = {
        "client1": create_password_hash(
            "password123"
        ),
        "client2": create_password_hash(
            "password456"
        ),
    }

    generate_certificate()

    context = ssl.SSLContext(
        ssl.PROTOCOL_TLS_SERVER
    )

    context.load_cert_chain(
        str(CERT_FILE),
        str(KEY_FILE),
    )

    threading.Thread(
        target=udp_endpoint_listener,
        args=(SERVER_HOST, UDP_PORT),
        daemon=True,
    ).start()

    server_socket = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM,
    )

    server_socket.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1,
    )

    server_socket.bind(
        (SERVER_HOST, TLS_PORT)
    )

    server_socket.listen(10)

    print(
        f"ZTNA TLS server listening on "
        f"{SERVER_HOST}:{TLS_PORT}"
    )

    while True:
        client_socket, _ = server_socket.accept()

        try:
            connection = context.wrap_socket(
                client_socket,
                server_side=True,
            )

            threading.Thread(
                target=handle_client,
                args=(connection, users),
                daemon=True,
            ).start()

        except Exception as exc:
            print(f"Client error: {exc}")

            try:
                client_socket.close()
            except OSError:
                pass


if __name__ == "__main__":
    main()