import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


KEY_SIZE = 32
NONCE_SIZE = 12


def generate_key_pair() -> tuple[
    X25519PrivateKey,
    bytes,
]:
    """Generate an X25519 key pair."""

    private_key = X25519PrivateKey.generate()

    public_key = private_key.public_key().public_bytes_raw()

    return private_key, public_key


def exchange_keys(
    private_key: X25519PrivateKey,
    peer_public_key: X25519PublicKey,
) -> bytes:
    """Perform X25519 key exchange."""

    if not isinstance(
        private_key,
        X25519PrivateKey,
    ):
        raise TypeError(
            "Invalid private key"
        )

    if not isinstance(
        peer_public_key,
        X25519PublicKey,
    ):
        raise TypeError(
            "Invalid peer public key"
        )

    return private_key.exchange(
        peer_public_key
    )


def derive_shared_key(
    shared_secret: bytes,
) -> bytes:
    """Derive an AES-256 key using HKDF-SHA256."""

    if not shared_secret:
        raise ValueError(
            "Shared secret is required"
        )

    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=None,
        info=b"ZTNA-v1",
    ).derive(shared_secret)


def encrypt(
    key: bytes,
    plaintext: bytes,
) -> tuple[bytes, bytes]:
    """Encrypt plaintext with AES-256-GCM."""

    if len(key) != KEY_SIZE:
        raise ValueError(
            "AES-256 key must be 32 bytes"
        )

    nonce = os.urandom(NONCE_SIZE)

    ciphertext = AESGCM(key).encrypt(
        nonce,
        plaintext,
        None,
    )

    return nonce, ciphertext


def decrypt(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
) -> bytes:
    """Decrypt AES-256-GCM ciphertext."""

    if len(key) != KEY_SIZE:
        raise ValueError(
            "AES-256 key must be 32 bytes"
        )

    if len(nonce) != NONCE_SIZE:
        raise ValueError(
            "AES-GCM nonce must be 12 bytes"
        )

    return AESGCM(key).decrypt(
        nonce,
        ciphertext,
        None,
    )