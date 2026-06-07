"""
VaultLink — Crypto Core
AES-256-GCM encryption + HMAC-SHA256 integrity for file transfer and storage.
"""

import os
import hmac
import hashlib
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Constants
AES_KEY_SIZE    = 32        # 256-bit
HMAC_KEY_SIZE   = 32        # 256-bit
NONCE_SIZE      = 12        # 96-bit GCM nonce
SALT_SIZE       = 32        # PBKDF2 salt
PBKDF2_ITERS    = 600_000
CHUNK_SIZE      = 64 * 1024 # 64 KB chunks


def derive_keys(password: str, salt: bytes) -> tuple[bytes, bytes]:
    """Derive AES key and HMAC key from a password via PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE + HMAC_KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERS,
        backend=default_backend(),
    )
    key_material = kdf.derive(password.encode())
    aes_key  = key_material[:AES_KEY_SIZE]
    hmac_key = key_material[AES_KEY_SIZE:]
    return aes_key, hmac_key


def generate_salt() -> bytes:
    return os.urandom(SALT_SIZE)


def generate_nonce() -> bytes:
    return os.urandom(NONCE_SIZE)


# ── Encrypt / Decrypt (in-memory, for small files) ──────────────────────────

def encrypt_data(plaintext: bytes, aes_key: bytes, hmac_key: bytes) -> bytes:
    """
    Layout: NONCE(12) | CIPHERTEXT | HMAC(32)
    HMAC covers NONCE + CIPHERTEXT.
    """
    nonce      = generate_nonce()
    aesgcm     = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    payload  = nonce + ciphertext
    mac      = hmac.new(hmac_key, payload, hashlib.sha256).digest()
    return payload + mac


def decrypt_data(blob: bytes, aes_key: bytes, hmac_key: bytes) -> bytes:
    """Verify HMAC then decrypt."""
    if len(blob) < NONCE_SIZE + 16 + 32:
        raise ValueError("Blob too short to be valid ciphertext.")

    payload, mac = blob[:-32], blob[-32:]

    expected_mac = hmac.new(hmac_key, payload, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected_mac):
        raise ValueError("HMAC verification failed — data may be tampered.")

    nonce      = payload[:NONCE_SIZE]
    ciphertext = payload[NONCE_SIZE:]
    aesgcm     = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ciphertext, None)


# ── Chunked streaming encrypt / decrypt (for large files) ───────────────────

def encrypt_file_to_stream(src_path: str, dest_path: str, aes_key: bytes, hmac_key: bytes):
    """
    Encrypt a file in 64 KB chunks.

    Stream layout:
        [4-byte chunk_count] [chunk_0] [chunk_1] ... [HMAC-32]

    Each chunk:
        [4-byte chunk_len] [NONCE(12)] [AES-GCM ciphertext]

    HMAC covers everything before the trailing MAC.
    """
    aesgcm  = AESGCM(aes_key)
    h       = hmac.new(hmac_key, digestmod=hashlib.sha256)
    chunks  = []

    with open(src_path, "rb") as f:
        while True:
            plaintext = f.read(CHUNK_SIZE)
            if not plaintext:
                break
            nonce      = generate_nonce()
            ciphertext = aesgcm.encrypt(nonce, plaintext, None)
            chunk      = nonce + ciphertext
            chunks.append(chunk)

    with open(dest_path, "wb") as out:
        count_bytes = struct.pack(">I", len(chunks))
        out.write(count_bytes)
        h.update(count_bytes)

        for chunk in chunks:
            length_bytes = struct.pack(">I", len(chunk))
            out.write(length_bytes)
            out.write(chunk)
            h.update(length_bytes)
            h.update(chunk)

        out.write(h.digest())


def decrypt_stream_to_file(src_path: str, dest_path: str, aes_key: bytes, hmac_key: bytes):
    """Verify HMAC then decrypt a chunked stream back to a file."""
    aesgcm = AESGCM(aes_key)

    with open(src_path, "rb") as f:
        raw = f.read()

    if len(raw) < 36:   # 4 (count) + 32 (HMAC) minimum
        raise ValueError("File too short.")

    payload, mac = raw[:-32], raw[-32:]
    h = hmac.new(hmac_key, payload, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, h):
        raise ValueError("HMAC verification failed — file may be corrupted or tampered.")

    offset      = 0
    chunk_count = struct.unpack(">I", payload[offset:offset+4])[0]
    offset     += 4

    with open(dest_path, "wb") as out:
        for _ in range(chunk_count):
            if offset + 4 > len(payload):
                raise ValueError("Unexpected end of stream while reading chunk length.")
            chunk_len = struct.unpack(">I", payload[offset:offset+4])[0]
            offset   += 4

            chunk = payload[offset:offset+chunk_len]
            offset += chunk_len

            nonce      = chunk[:NONCE_SIZE]
            ciphertext = chunk[NONCE_SIZE:]
            plaintext  = aesgcm.decrypt(nonce, ciphertext, None)
            out.write(plaintext)
