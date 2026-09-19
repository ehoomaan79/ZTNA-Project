import base64
import json
import struct
from typing import Any


AUTH = "AUTH"
AUTH_RESPONSE = "AUTH_RESPONSE"
TOKEN = "TOKEN"
KEY_EXCHANGE = "KEY_EXCHANGE"
PEER_REQUEST = "PEER_REQUEST"
ENDPOINT_INFO = "ENDPOINT_INFO"
NAT_PROBE = "NAT_PROBE"
DATA = "DATA"
CLOSE = "CLOSE"


REQUIRED_FIELDS = {
    AUTH: (
        "username",
        "password",
    ),
    AUTH_RESPONSE: (
        "status",
        "message",
    ),
    TOKEN: (
        "token",
        "expires_at",
    ),
    KEY_EXCHANGE: (
        "public_key",
    ),
    PEER_REQUEST: (
        "token",
        "peer_id",
    ),
    ENDPOINT_INFO: (
        "client_id",
        "public_ip",
        "public_port",
        "public_key",
    ),
    NAT_PROBE: (
        "client_id",
        "timestamp",
    ),
    DATA: (
        "nonce",
        "ciphertext",
    ),
    CLOSE: (
        "reason",
    ),
}


MAX_MESSAGE_SIZE = 1024 * 1024


def create_message(
    message_type: str,
    **fields: Any,
) -> bytes:
    if message_type not in REQUIRED_FIELDS:
        raise ValueError(
            f"Unknown message type: {message_type}"
        )

    message = {
        "type": message_type,
        **fields,
    }

    _validate_message(message)

    payload = json.dumps(
        message,
        separators=(",", ":"),
    ).encode("utf-8")

    if len(payload) > MAX_MESSAGE_SIZE:
        raise ValueError(
            "Message is too large"
        )

    return struct.pack(
        "!I",
        len(payload),
    ) + payload


def receive_message(sock) -> dict:
    header = _receive_exact(
        sock,
        4,
    )

    length = struct.unpack(
        "!I",
        header,
    )[0]

    if length <= 0 or length > MAX_MESSAGE_SIZE:
        raise ValueError(
            "Invalid message length"
        )

    payload = _receive_exact(
        sock,
        length,
    )

    return parse_message(payload)


def parse_message(
    data: bytes,
) -> dict:
    if not isinstance(data, bytes):
        raise TypeError(
            "Message must be bytes"
        )

    try:
        message = json.loads(
            data.decode("utf-8")
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as exc:
        raise ValueError(
            "Invalid message"
        ) from exc

    _validate_message(message)

    return message


def parse_datagram(
    data: bytes,
) -> dict:
    if len(data) < 4:
        raise ValueError(
            "Invalid datagram"
        )

    length = struct.unpack(
        "!I",
        data[:4],
    )[0]

    payload = data[4:]

    if length != len(payload):
        raise ValueError(
            "Invalid datagram length"
        )

    if length <= 0 or length > MAX_MESSAGE_SIZE:
        raise ValueError(
            "Invalid datagram size"
        )

    return parse_message(payload)


def encode_bytes(
    data: bytes,
) -> str:
    return base64.b64encode(
        data
    ).decode("ascii")


def decode_bytes(
    data: str,
) -> bytes:
    if not isinstance(data, str):
        raise TypeError(
            "Encoded value must be a string"
        )

    try:
        return base64.b64decode(
            data,
            validate=True,
        )
    except ValueError as exc:
        raise ValueError(
            "Invalid base64 data"
        ) from exc


def _receive_exact(
    sock,
    size: int,
) -> bytes:
    data = bytearray()

    while len(data) < size:
        chunk = sock.recv(
            size - len(data)
        )

        if not chunk:
            raise ConnectionError(
                "Connection closed"
            )

        data.extend(chunk)

    return bytes(data)


def _validate_message(
    message: dict,
) -> None:
    if not isinstance(
        message,
        dict,
    ):
        raise ValueError(
            "Message must be an object"
        )

    message_type = message.get("type")

    if message_type not in REQUIRED_FIELDS:
        raise ValueError(
            "Unknown message type"
        )

    for field in REQUIRED_FIELDS[
        message_type
    ]:
        if field not in message:
            raise ValueError(
                f"Missing field: {field}"
            )