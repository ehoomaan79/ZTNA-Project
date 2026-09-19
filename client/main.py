import argparse
import socket
import time

from client.connection import (
    connect_to_server,
    close_connection,
)

from common.network import (
    perform_nat_traversal,
)

from common.protocol import (
    AUTH,
    AUTH_RESPONSE,
    TOKEN,
    KEY_EXCHANGE,
    PEER_REQUEST,
    ENDPOINT_INFO,
    DATA,
    create_message,
    receive_message,
    parse_datagram,
    encode_bytes,
    decode_bytes,
)

from common.security import (
    generate_key_pair,
    exchange_keys,
    derive_shared_key,
    encrypt,
    decrypt,
)

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PublicKey,
)


UDP_REGISTRATION_ATTEMPTS = 10
UDP_REGISTRATION_TIMEOUT = 2
UDP_REGISTRATION_INTERVAL = 0.5


def authenticate_with_server(
    connection,
    username,
    password,
):
    connection.sendall(
        create_message(
            AUTH,
            username=username,
            password=password,
        )
    )

    response = receive_message(connection)

    if response["type"] != AUTH_RESPONSE:
        return None

    if response["status"] != "allow":
        print(response["message"])
        return None

    token_message = receive_message(connection)

    if token_message["type"] != TOKEN:
        return None

    return token_message["token"]


def send_public_key(
    connection,
    public_key,
):
    connection.sendall(
        create_message(
            KEY_EXCHANGE,
            public_key=encode_bytes(public_key),
        )
    )


def register_udp_endpoint(
    sock,
    server_host,
    server_port,
    client_id,
):
    sock.settimeout(UDP_REGISTRATION_TIMEOUT)

    for _ in range(UDP_REGISTRATION_ATTEMPTS):
        probe = (
            f"NAT_PROBE:{client_id}:{time.time()}"
        ).encode()

        sock.sendto(
            probe,
            (server_host, server_port),
        )

        try:
            data, _ = sock.recvfrom(1024)

            if data == b"NAT_ACK":
                sock.settimeout(None)
                return

        except socket.timeout:
            time.sleep(
                UDP_REGISTRATION_INTERVAL
            )

    sock.settimeout(None)

    raise ConnectionError(
        "UDP endpoint registration failed"
    )


def request_peer(
    connection,
    token,
    peer_id,
):
    connection.sendall(
        create_message(
            PEER_REQUEST,
            token=token,
            peer_id=peer_id,
        )
    )

    return receive_message(connection)


def send_peer_data(
    sock,
    shared_key,
    text,
):
    nonce, ciphertext = encrypt(
        shared_key,
        text.encode("utf-8"),
    )

    packet = create_message(
        DATA,
        nonce=encode_bytes(nonce),
        ciphertext=encode_bytes(ciphertext),
    )

    sock.send(packet)


def receive_peer_data(
    sock,
    shared_key,
):
    while True:
        try:
            data = sock.recv(65535)

        except ConnectionRefusedError:
            continue

        except socket.timeout:
            return None

        if not data:
            return None

        try:
            message = parse_datagram(data)
        except ValueError:
            continue

        if message["type"] != DATA:
            continue

        plaintext = decrypt(
            shared_key,
            decode_bytes(message["nonce"]),
            decode_bytes(message["ciphertext"]),
        )

        return plaintext.decode("utf-8")


def main():
    parser = argparse.ArgumentParser(
        description="ZTNA Client"
    )

    parser.add_argument(
        "--server",
        required=True,
    )

    parser.add_argument(
        "--port",
        type=int,
        default=8443,
    )

    parser.add_argument(
        "--udp-port",
        type=int,
        default=8444,
    )

    parser.add_argument(
        "--cafile",
        required=True,
    )

    parser.add_argument(
        "--username",
        required=True,
    )

    parser.add_argument(
        "--password",
        required=True,
    )

    parser.add_argument(
        "--peer",
    )

    args = parser.parse_args()

    connection = connect_to_server(
        args.server,
        args.port,
        args.cafile,
    )

    udp_socket = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM,
    )

    udp_socket.bind(
        ("0.0.0.0", 0)
    )

    try:
        token = authenticate_with_server(
            connection,
            args.username,
            args.password,
        )

        if not token:
            return

        private_key, public_key = (
            generate_key_pair()
        )

        send_public_key(
            connection,
            public_key,
        )

        register_udp_endpoint(
            udp_socket,
            args.server,
            args.udp_port,
            args.username,
        )

        print("Authentication successful.")
        print("UDP endpoint registered.")

        if not args.peer:
            while True:
                message = receive_message(
                    connection
                )

                if message["type"] != ENDPOINT_INFO:
                    continue

                peer_endpoint = message

                peer_public_key = (
                    X25519PublicKey.from_public_bytes(
                        decode_bytes(
                            peer_endpoint["public_key"]
                        )
                    )
                )

                shared_secret = exchange_keys(
                    private_key,
                    peer_public_key,
                )

                shared_key = derive_shared_key(
                    shared_secret
                )

                peer_address = (
                    peer_endpoint["public_ip"],
                    peer_endpoint["public_port"],
                )

                udp_socket.connect(
                    peer_address
                )

                if perform_nat_traversal(
                    udp_socket,
                    peer_address,
                    args.username,
                ):
                    print(
                        "Direct peer connection established."
                    )

                    send_peer_data(
                        udp_socket,
                        shared_key,
                        f"Hello from {args.username}",
                    )

            return

        endpoint = request_peer(
            connection,
            token,
            args.peer,
        )

        if endpoint["type"] != ENDPOINT_INFO:
            print(
                endpoint.get(
                    "message",
                    "Peer request denied.",
                )
            )
            return

        peer_public_key = (
            X25519PublicKey.from_public_bytes(
                decode_bytes(
                    endpoint["public_key"]
                )
            )
        )

        shared_secret = exchange_keys(
            private_key,
            peer_public_key,
        )

        shared_key = derive_shared_key(
            shared_secret
        )

        peer_address = (
            endpoint["public_ip"],
            endpoint["public_port"],
        )

        udp_socket.connect(
            peer_address
        )

        if not perform_nat_traversal(
            udp_socket,
            peer_address,
            args.username,
        ):
            print("NAT traversal failed.")
            return

        print(
            "Direct peer connection established."
        )

        send_peer_data(
            udp_socket,
            shared_key,
            f"Hello from {args.username}",
        )

        print("Encrypted message sent.")

        message = receive_peer_data(
            udp_socket,
            shared_key,
        )

        if message:
            print(
                f"Received: {message}"
            )

    finally:
        udp_socket.close()
        close_connection(connection)


if __name__ == "__main__":
    main()