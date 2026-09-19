import hashlib
import hmac
import secrets
import time


PBKDF2_ITERATIONS = 200_000


def create_password_hash(password: str) -> str:
    """Create a PBKDF2 password hash."""

    if not password:
        raise ValueError("Password is required")

    salt = secrets.token_bytes(16)

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
    ).hex()

    return f"{salt.hex()}:{password_hash}"


def authenticate_client(
    username: str,
    password: str,
    users: dict[str, str],
) -> bool:
    """Authenticate a client."""

    stored = users.get(username)

    if not stored:
        return False

    try:
        salt_hex, stored_hash = stored.split(":", 1)
        salt = bytes.fromhex(salt_hex)
    except ValueError:
        return False

    calculated_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
    ).hex()

    return hmac.compare_digest(
        calculated_hash,
        stored_hash,
    )


def check_access(
    client_id: str,
    peer_id: str,
    access_list: set[tuple[str, str]],
) -> bool:
    """Check whether a client may communicate with a peer."""

    return (client_id, peer_id) in access_list


def create_token(
    client_id: str,
    expires_in: int = 3600,
) -> tuple[str, int]:
    """Create a random time-limited access token."""

    if not client_id:
        raise ValueError("Client ID is required")

    if expires_in <= 0:
        raise ValueError("Token lifetime must be positive")

    token = secrets.token_urlsafe(32)
    expires_at = int(time.time()) + expires_in

    return token, expires_at


def validate_token(
    client_id: str,
    token: str,
    session: dict | None,
) -> bool:
    """Validate a client's active session token."""

    if not session:
        return False

    if not token:
        return False

    if session.get("token") != token:
        return False

    if session.get("expires_at", 0) <= int(time.time()):
        return False

    return bool(client_id)