#!/usr/bin/env python3
"""
VaultLink — Client
Encrypt files locally, upload to server, download and decrypt.

Usage:
  python client.py upload   <file>           --password <pass> [--host HOST] [--port PORT]
  python client.py download <remote_name>    --password <pass> [--out DIR]
  python client.py list
  python client.py delete   <remote_name>    --password <pass>

All encryption/decryption happens on the CLIENT. The server only stores
AES-256-GCM encrypted blobs and never sees plaintext.
"""

import os
import sys
import json
import struct
import socket
import hashlib
import argparse
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from crypto_core import (
    derive_keys, generate_salt,
    encrypt_file_to_stream, decrypt_stream_to_file,
    encrypt_data, decrypt_data,
    CHUNK_SIZE,
)

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 9999
BUFFER       = 65536


# ── Socket helpers ────────────────────────────────────────────────────────────

def send_message(sock: socket.socket, header: dict, payload: bytes = b""):
    header["payload_size"] = len(payload)
    header_bytes = json.dumps(header).encode()
    frame = struct.pack(">I", len(header_bytes)) + header_bytes + payload
    sock.sendall(frame)


def recv_message(sock: socket.socket) -> tuple[dict, bytes]:
    def recv_exact(n):
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("Connection closed unexpectedly.")
            buf += chunk
        return buf

    raw_len   = recv_exact(4)
    hdr_len   = struct.unpack(">I", raw_len)[0]
    hdr_bytes = recv_exact(hdr_len)
    header    = json.loads(hdr_bytes.decode())

    payload_size = header.get("payload_size", 0)
    payload = recv_exact(payload_size) if payload_size > 0 else b""
    return header, payload


def connect(host: str, port: int) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    return sock


# ── Commands ─────────────────────────────────────────────────────────────────

def cmd_upload(args):
    src = Path(args.file)
    if not src.exists():
        print(f"[ERROR] File not found: {src}")
        sys.exit(1)

    password    = args.password
    salt        = generate_salt()
    aes_key, hmac_key = derive_keys(password, salt)

    print(f"[*] Encrypting  {src.name} ({src.stat().st_size:,} bytes)...")
    t0 = time.time()

    with tempfile.NamedTemporaryFile(delete=False, suffix=".enc") as tmp:
        tmp_path = tmp.name

    try:
        encrypt_file_to_stream(str(src), tmp_path, aes_key, hmac_key)
        enc_bytes  = Path(tmp_path).read_bytes()
        sha256_hex = hashlib.sha256(enc_bytes).hexdigest()

        elapsed = time.time() - t0
        print(f"[*] Encrypted in {elapsed:.2f}s → {len(enc_bytes):,} bytes")
        print(f"[*] Connecting to {args.host}:{args.port} ...")

        sock = connect(args.host, args.port)

        print(f"[*] Uploading...")
        send_message(sock, {
            "cmd":       "UPLOAD",
            "filename":  src.name,
            "salt":      salt.hex(),
            "hmac_check": sha256_hex,
        }, enc_bytes)

        resp, _ = recv_message(sock)
        sock.close()

        if resp["status"] == "ok":
            print(f"[✓] {resp['message']}")
        else:
            print(f"[ERROR] {resp['message']}")
            sys.exit(1)

    finally:
        os.unlink(tmp_path)


def cmd_download(args):
    password = args.password
    out_dir  = Path(args.out) if args.out else Path(".")
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"[*] Connecting to {args.host}:{args.port} ...")
    sock = connect(args.host, args.port)
    send_message(sock, {"cmd": "DOWNLOAD", "filename": args.filename})
    resp, payload = recv_message(sock)
    sock.close()

    if resp["status"] != "ok":
        print(f"[ERROR] {resp['message']}")
        sys.exit(1)

    # Verify transfer integrity
    actual_sha256 = hashlib.sha256(payload).hexdigest()
    if actual_sha256 != resp.get("sha256", ""):
        print("[ERROR] Transfer integrity check failed — aborting.")
        sys.exit(1)

    salt_hex = resp.get("salt", "")
    if not salt_hex:
        print("[ERROR] Server did not return salt — cannot decrypt.")
        sys.exit(1)

    salt = bytes.fromhex(salt_hex)
    aes_key, hmac_key = derive_keys(password, salt)

    out_path = out_dir / args.filename
    print(f"[*] Decrypting {len(payload):,} bytes ...")

    with tempfile.NamedTemporaryFile(delete=False, suffix=".enc") as tmp:
        tmp.write(payload)
        tmp_path = tmp.name

    try:
        t0 = time.time()
        decrypt_stream_to_file(tmp_path, str(out_path), aes_key, hmac_key)
        elapsed = time.time() - t0
        print(f"[✓] Decrypted in {elapsed:.2f}s → {out_path} ({out_path.stat().st_size:,} bytes)")
    except ValueError as e:
        print(f"[ERROR] Decryption failed: {e}")
        if out_path.exists():
            out_path.unlink()
        sys.exit(1)
    finally:
        os.unlink(tmp_path)


def cmd_list(args):
    print(f"[*] Connecting to {args.host}:{args.port} ...")
    sock = connect(args.host, args.port)
    send_message(sock, {"cmd": "LIST"})
    resp, _ = recv_message(sock)
    sock.close()

    if resp["status"] != "ok":
        print(f"[ERROR] {resp['message']}")
        sys.exit(1)

    files = resp.get("files", [])
    if not files:
        print("(vault is empty)")
        return

    print(f"\n{'FILENAME':<35} {'ENC SIZE':>12}  UPLOADED")
    print("─" * 70)
    for f in files:
        size_kb = f['size'] / 1024
        print(f"{f['filename']:<35} {size_kb:>10.1f}K  {f.get('uploaded','?')}")
    print(f"\n{len(files)} file(s) stored.\n")


def cmd_delete(args):
    print(f"[*] Connecting to {args.host}:{args.port} ...")
    sock = connect(args.host, args.port)
    send_message(sock, {"cmd": "DELETE", "filename": args.filename})
    resp, _ = recv_message(sock)
    sock.close()

    if resp["status"] == "ok":
        print(f"[✓] {resp['message']}")
    else:
        print(f"[ERROR] {resp['message']}")
        sys.exit(1)


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="vaultlink",
        description="VaultLink — Encrypted File Transfer Client",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python client.py upload   secret.pdf  --password hunter2
  python client.py download secret.pdf  --password hunter2 --out ~/Downloads
  python client.py list
  python client.py delete   secret.pdf
        """
    )

    parser.add_argument("--host", default=DEFAULT_HOST, help=f"Server host (default: {DEFAULT_HOST})")
    parser.add_argument("--port", default=DEFAULT_PORT, type=int, help=f"Server port (default: {DEFAULT_PORT})")

    sub = parser.add_subparsers(dest="cmd", required=True)

    # upload
    p_up = sub.add_parser("upload", help="Encrypt and upload a file")
    p_up.add_argument("file")
    p_up.add_argument("--password", required=True)

    # download
    p_dl = sub.add_parser("download", help="Download and decrypt a file")
    p_dl.add_argument("filename")
    p_dl.add_argument("--password", required=True)
    p_dl.add_argument("--out", default=".", help="Output directory (default: current dir)")

    # list
    sub.add_parser("list", help="List stored files")

    # delete
    p_del = sub.add_parser("delete", help="Delete a file from the vault")
    p_del.add_argument("filename")

    args = parser.parse_args()

    dispatch = {
        "upload":   cmd_upload,
        "download": cmd_download,
        "list":     cmd_list,
        "delete":   cmd_delete,
    }
    dispatch[args.cmd](args)


if __name__ == "__main__":
    main()
