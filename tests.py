#!/usr/bin/env python3
"""
VaultLink — Self-Test Suite
Runs unit tests for crypto_core and an integration test
(in-process, no real server socket needed).
"""

import os
import sys
import json
import time
import struct
import hashlib
import tempfile
import unittest
import threading
import socket
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from crypto_core import (
    derive_keys, generate_salt, generate_nonce,
    encrypt_data, decrypt_data,
    encrypt_file_to_stream, decrypt_stream_to_file,
    CHUNK_SIZE,
)


# ── Unit Tests ────────────────────────────────────────────────────────────────

class TestDeriveKeys(unittest.TestCase):
    def test_deterministic(self):
        salt = generate_salt()
        k1_a, k1_b = derive_keys("password", salt)
        k2_a, k2_b = derive_keys("password", salt)
        self.assertEqual(k1_a, k2_a)
        self.assertEqual(k1_b, k2_b)

    def test_different_passwords(self):
        salt = generate_salt()
        ka, _ = derive_keys("pass1", salt)
        kb, _ = derive_keys("pass2", salt)
        self.assertNotEqual(ka, kb)

    def test_different_salts(self):
        ka, _ = derive_keys("password", generate_salt())
        kb, _ = derive_keys("password", generate_salt())
        self.assertNotEqual(ka, kb)


class TestEncryptDecrypt(unittest.TestCase):
    def setUp(self):
        salt = generate_salt()
        self.aes_key, self.hmac_key = derive_keys("testpass", salt)

    def test_roundtrip_small(self):
        plaintext = b"Hello, VaultLink!"
        blob      = encrypt_data(plaintext, self.aes_key, self.hmac_key)
        recovered = decrypt_data(blob, self.aes_key, self.hmac_key)
        self.assertEqual(plaintext, recovered)

    def test_roundtrip_empty(self):
        plaintext = b""
        blob      = encrypt_data(plaintext, self.aes_key, self.hmac_key)
        recovered = decrypt_data(blob, self.aes_key, self.hmac_key)
        self.assertEqual(plaintext, recovered)

    def test_roundtrip_large(self):
        plaintext = os.urandom(256 * 1024)  # 256 KB
        blob      = encrypt_data(plaintext, self.aes_key, self.hmac_key)
        recovered = decrypt_data(blob, self.aes_key, self.hmac_key)
        self.assertEqual(plaintext, recovered)

    def test_tamper_detection(self):
        blob        = encrypt_data(b"secret", self.aes_key, self.hmac_key)
        tampered    = bytearray(blob)
        tampered[5] ^= 0xFF
        with self.assertRaises(Exception):
            decrypt_data(bytes(tampered), self.aes_key, self.hmac_key)

    def test_wrong_key(self):
        blob = encrypt_data(b"secret", self.aes_key, self.hmac_key)
        bad_aes, bad_hmac = derive_keys("wrongpass", generate_salt())
        with self.assertRaises(Exception):
            decrypt_data(blob, bad_aes, bad_hmac)


class TestChunkedStream(unittest.TestCase):
    def _roundtrip(self, size: int):
        salt = generate_salt()
        aes_key, hmac_key = derive_keys("chunktest", salt)
        plaintext = os.urandom(size)

        with tempfile.NamedTemporaryFile(delete=False) as src_f:
            src_f.write(plaintext)
            src_path = src_f.name

        enc_path = src_path + ".enc"
        dec_path = src_path + ".dec"

        try:
            encrypt_file_to_stream(src_path, enc_path, aes_key, hmac_key)
            decrypt_stream_to_file(enc_path, dec_path, aes_key, hmac_key)
            recovered = Path(dec_path).read_bytes()
            self.assertEqual(plaintext, recovered)
        finally:
            for p in [src_path, enc_path, dec_path]:
                if os.path.exists(p):
                    os.unlink(p)

    def test_small_file(self):         self._roundtrip(1024)
    def test_exact_chunk(self):        self._roundtrip(CHUNK_SIZE)
    def test_multi_chunk(self):        self._roundtrip(CHUNK_SIZE * 3 + 7777)
    def test_large_file(self):         self._roundtrip(4 * 1024 * 1024)   # 4 MB

    def test_tamper_detection(self):
        salt = generate_salt()
        aes_key, hmac_key = derive_keys("chunktest", salt)
        plaintext = os.urandom(1024)

        with tempfile.NamedTemporaryFile(delete=False) as src_f:
            src_f.write(plaintext)
            src_path = src_f.name

        enc_path = src_path + ".enc"
        dec_path = src_path + ".dec"

        try:
            encrypt_file_to_stream(src_path, enc_path, aes_key, hmac_key)
            data = bytearray(Path(enc_path).read_bytes())
            data[20] ^= 0xFF
            Path(enc_path).write_bytes(bytes(data))

            with self.assertRaises(Exception):
                decrypt_stream_to_file(enc_path, dec_path, aes_key, hmac_key)
        finally:
            for p in [src_path, enc_path, dec_path]:
                if os.path.exists(p):
                    os.unlink(p)


# ── Integration Test ──────────────────────────────────────────────────────────

class TestIntegration(unittest.TestCase):
    """
    Spins up the real server in a daemon thread, exercises upload/download/list/delete
    using the actual client functions (without subprocess).
    """

    @classmethod
    def setUpClass(cls):
        import importlib, sys as _sys

        # Patch storage dir so we don't pollute real vault
        cls.tmp_dir = tempfile.mkdtemp()

        # Import server module and point its STORAGE_DIR at tmp
        import server as srv_module
        srv_module.STORAGE_DIR = Path(cls.tmp_dir)
        cls.srv = srv_module

        # Start server on a random port
        cls.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        cls.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        cls.server_sock.bind(("127.0.0.1", 0))
        cls.port = cls.server_sock.getsockname()[1]
        cls.server_sock.listen(10)

        def serve():
            while True:
                try:
                    conn, addr = cls.server_sock.accept()
                    t = threading.Thread(
                        target=srv_module.client_handler,
                        args=(conn, addr),
                        daemon=True
                    )
                    t.start()
                except OSError:
                    break

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        time.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        cls.server_sock.close()
        import shutil
        shutil.rmtree(cls.tmp_dir, ignore_errors=True)

    def _client_sock(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("127.0.0.1", self.port))
        return s

    def _send(self, sock, header, payload=b""):
        self.srv.send_message(sock, header, payload)

    def _recv(self, sock):
        return self.srv.recv_message(sock)

    def test_upload_download_delete(self):
        password  = "integration_test_pass"
        plaintext = os.urandom(200 * 1024)   # 200 KB

        salt = generate_salt()
        aes_key, hmac_key = derive_keys(password, salt)

        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(plaintext)
            src_path = f.name

        enc_path = src_path + ".enc"

        try:
            encrypt_file_to_stream(src_path, enc_path, aes_key, hmac_key)
            enc_bytes  = Path(enc_path).read_bytes()
            sha256_hex = hashlib.sha256(enc_bytes).hexdigest()
            filename   = Path(src_path).name

            # -- Upload --
            sock = self._client_sock()
            self._send(sock, {
                "cmd":       "UPLOAD",
                "filename":  filename,
                "salt":      salt.hex(),
                "hmac_check": sha256_hex,
            }, enc_bytes)
            resp, _ = self._recv(sock)
            sock.close()
            self.assertEqual(resp["status"], "ok")

            # -- List --
            sock = self._client_sock()
            self._send(sock, {"cmd": "LIST"})
            resp, _ = self._recv(sock)
            sock.close()
            self.assertEqual(resp["status"], "ok")
            names = [f["filename"] for f in resp["files"]]
            self.assertIn(filename, names)

            # -- Download --
            sock = self._client_sock()
            self._send(sock, {"cmd": "DOWNLOAD", "filename": filename})
            resp, payload = self._recv(sock)
            sock.close()
            self.assertEqual(resp["status"], "ok")

            # Verify integrity
            dl_sha256 = hashlib.sha256(payload).hexdigest()
            self.assertEqual(dl_sha256, resp["sha256"])

            # Decrypt
            dl_salt = bytes.fromhex(resp["salt"])
            dl_aes, dl_hmac = derive_keys(password, dl_salt)

            dec_path = src_path + ".dec"
            with tempfile.NamedTemporaryFile(delete=False, suffix=".enc") as tmp:
                tmp.write(payload)
                dl_enc_path = tmp.name

            decrypt_stream_to_file(dl_enc_path, dec_path, dl_aes, dl_hmac)
            recovered = Path(dec_path).read_bytes()
            self.assertEqual(plaintext, recovered)

            # -- Delete --
            sock = self._client_sock()
            self._send(sock, {"cmd": "DELETE", "filename": filename})
            resp, _ = self._recv(sock)
            sock.close()
            self.assertEqual(resp["status"], "ok")

        finally:
            for p in [src_path, enc_path, dec_path if "dec_path" in dir() else "", dl_enc_path if "dl_enc_path" in dir() else ""]:
                if p and os.path.exists(p):
                    os.unlink(p)


if __name__ == "__main__":
    print("=" * 60)
    print("  VaultLink — Self-Test Suite")
    print("=" * 60)
    unittest.main(verbosity=2)
