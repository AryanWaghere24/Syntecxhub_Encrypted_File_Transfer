#!/usr/bin/env python3
"""
VaultLink — Server
Receives encrypted file uploads, stores them on disk, serves them back.
Files are NEVER stored in plaintext; encryption/decryption happens at the client.

Protocol (over raw TCP):
  Every message:  [4-byte big-endian length][JSON header][optional binary payload]

Commands (client → server):
  UPLOAD   { filename, size, salt (hex), hmac_check (hex) } + encrypted bytes
  DOWNLOAD { filename }
  LIST     {}
  DELETE   { filename }

Responses (server → client):
  { "status": "ok"|"error", "message": "...", ...extra }
"""

import os
import json
import struct
import socket
import threading
import hashlib
import time
from pathlib import Path

STORAGE_DIR  = Path("vault_storage")
HOST         = "0.0.0.0"
PORT         = 9999
MAX_FILE_MB  = 512
BUFFER       = 4096


def log(tag: str, msg: str):
    ts = time.strftime("%H:%M:%S")
    print(f"[{ts}] [{tag}] {msg}")


def send_message(sock: socket.socket, header: dict, payload: bytes = b""):
    header = dict(header)                           # don't mutate caller's dict
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


def handle_upload(sock: socket.socket, header: dict, payload: bytes):
    filename   = header.get("filename", "")
    salt_hex   = header.get("salt", "")
    hmac_check = header.get("hmac_check", "")    # SHA-256 of the raw encrypted blob

    if not filename or "/" in filename or ".." in filename:
        send_message(sock, {"status": "error", "message": "Invalid filename."})
        return

    # Verify transfer integrity (SHA-256 of the encrypted blob)
    actual_hash = hashlib.sha256(payload).hexdigest()
    if actual_hash != hmac_check:
        send_message(sock, {"status": "error", "message": "Transfer integrity check failed (SHA-256 mismatch)."})
        log("UPLOAD", f"REJECTED {filename} — hash mismatch")
        return

    dest = STORAGE_DIR / filename
    meta = STORAGE_DIR / (filename + ".meta")

    dest.write_bytes(payload)
    meta.write_text(json.dumps({
        "filename":  filename,
        "salt":      salt_hex,
        "size":      len(payload),
        "uploaded":  time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sha256":    actual_hash,
    }))

    log("UPLOAD", f"Stored {filename} ({len(payload):,} bytes encrypted)")
    send_message(sock, {"status": "ok", "message": f"Stored {filename} successfully."})


def handle_download(sock: socket.socket, header: dict):
    filename = header.get("filename", "")

    if not filename or "/" in filename or ".." in filename:
        send_message(sock, {"status": "error", "message": "Invalid filename."})
        return

    dest = STORAGE_DIR / filename
    meta_path = STORAGE_DIR / (filename + ".meta")

    if not dest.exists():
        send_message(sock, {"status": "error", "message": f"{filename} not found."})
        return

    payload    = dest.read_bytes()
    meta       = json.loads(meta_path.read_text()) if meta_path.exists() else {}
    sha256_hex = hashlib.sha256(payload).hexdigest()

    log("DOWNLOAD", f"Serving {filename} ({len(payload):,} bytes encrypted)")
    send_message(sock, {
        "status":       "ok",
        "filename":     filename,
        "salt":         meta.get("salt", ""),
        "sha256":       sha256_hex,
        "payload_size": len(payload),
    }, payload)


def handle_list(sock: socket.socket):
    files = []
    for meta_path in sorted(STORAGE_DIR.glob("*.meta")):
        try:
            meta = json.loads(meta_path.read_text())
            files.append({
                "filename": meta["filename"],
                "size":     meta["size"],
                "uploaded": meta.get("uploaded", "unknown"),
            })
        except Exception:
            pass
    send_message(sock, {"status": "ok", "files": files})


def handle_delete(sock: socket.socket, header: dict):
    filename = header.get("filename", "")
    if not filename or "/" in filename or ".." in filename:
        send_message(sock, {"status": "error", "message": "Invalid filename."})
        return

    dest      = STORAGE_DIR / filename
    meta_path = STORAGE_DIR / (filename + ".meta")

    if not dest.exists():
        send_message(sock, {"status": "error", "message": f"{filename} not found."})
        return

    dest.unlink()
    if meta_path.exists():
        meta_path.unlink()

    log("DELETE", f"Deleted {filename}")
    send_message(sock, {"status": "ok", "message": f"{filename} deleted."})


def client_handler(sock: socket.socket, addr):
    log("CONN", f"New connection from {addr[0]}:{addr[1]}")
    try:
        while True:
            header, payload = recv_message(sock)
            cmd = header.get("cmd", "").upper()

            if cmd == "UPLOAD":
                handle_upload(sock, header, payload)
            elif cmd == "DOWNLOAD":
                handle_download(sock, header)
            elif cmd == "LIST":
                handle_list(sock)
            elif cmd == "DELETE":
                handle_delete(sock, header)
            elif cmd == "QUIT":
                break
            else:
                send_message(sock, {"status": "error", "message": f"Unknown command: {cmd}"})
    except (ConnectionError, struct.error, json.JSONDecodeError) as e:
        log("CONN", f"Connection from {addr[0]} closed: {e}")
    except Exception as e:
        log("ERROR", f"Unhandled error for {addr[0]}: {e}")
    finally:
        sock.close()
        log("CONN", f"Disconnected {addr[0]}:{addr[1]}")


def main():
    STORAGE_DIR.mkdir(exist_ok=True)
    log("SERVER", f"VaultLink server starting on {HOST}:{PORT}")
    log("SERVER", f"Storage directory: {STORAGE_DIR.resolve()}")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(10)
    log("SERVER", "Listening for connections...")

    try:
        while True:
            sock, addr = server.accept()
            t = threading.Thread(target=client_handler, args=(sock, addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        log("SERVER", "Shutting down.")
    finally:
        server.close()


if __name__ == "__main__":
    main()
