# VaultLink

```
 __   __           _ _   _     _       _    
 \ \ / /__ _ _  _| | |_| |   (_)_ __ | |__ 
  \ V / _` | || | |  _| |   | | '_ \| / / 
   \_/\__,_|\_,_|_|\__|_|   |_|_| |_|_\_\ 
        Encrypted File Transfer System
```

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)
![Crypto](https://img.shields.io/badge/AES--256--GCM-Encrypted-4CAF50?style=flat-square)
![HMAC](https://img.shields.io/badge/HMAC--SHA256-Integrity-orange?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)
![Tests](https://img.shields.io/badge/Tests-14%20Passing-brightgreen?style=flat-square)

A Python-based encrypted file transfer and secure storage system. Files are encrypted **on the client** before ever leaving your machine — the server stores and serves only ciphertext and never sees plaintext.

---

## 🔐 How It Works

```
CLIENT                              SERVER
  │                                   │
  │  derive_keys(password, salt)       │
  │  encrypt_file_to_stream()          │
  │  sha256(encrypted_blob)            │
  │                                   │
  │ ──── UPLOAD (enc blob + salt) ──► │  verify SHA-256
  │                                   │  store .bin + .meta
  │                                   │
  │ ◄──── DOWNLOAD (enc blob) ──────  │  serve encrypted blob
  │                                   │
  │  verify SHA-256                   │
  │  decrypt_stream_to_file()         │
  ▼                                   ▼
plaintext restored               never saw plaintext
```

---

## ✨ Features

- 🔒 **AES-256-GCM encryption** — authenticated encryption, every chunk independently sealed
- 🔑 **PBKDF2 key derivation** — 600,000 iterations, random salt per file, splits into AES + HMAC keys
- 🧾 **HMAC-SHA256 integrity** — covers the entire encrypted stream; one tampered byte = rejection
- 📦 **Chunked transfer** — files processed in 64 KB chunks, handles arbitrarily large files
- 🛡️ **Transfer integrity** — SHA-256 verified on both upload and download before touching disk
- 🗂️ **Encrypted-at-rest storage** — server stores only ciphertext + metadata (salt, timestamp, hash)
- 🔁 **Full CRUD** — upload, download, list, delete
- 🧵 **Multi-client server** — threaded TCP server, handles concurrent connections
- 🧪 **14 passing tests** — unit tests for crypto + full integration test (upload → download → decrypt → delete)

---

## 📊 Security Model

| Property | Mechanism |
|---|---|
| Confidentiality | AES-256-GCM (per-chunk nonce) |
| Integrity (stream) | HMAC-SHA256 over full ciphertext |
| Integrity (transfer) | SHA-256 checksum verified client ↔ server |
| Key derivation | PBKDF2-HMAC-SHA256, 600k iterations |
| Salt | 32-byte random, unique per file, stored server-side |
| Server knowledge | Salt + encrypted blob only — zero plaintext exposure |

---

## 🗂️ Project Structure

```
VaultLink/
├── crypto_core.py     # AES-256-GCM + HMAC + chunked stream encrypt/decrypt
├── server.py          # Multi-threaded TCP vault server
├── client.py          # CLI client — encrypt locally, upload/download/list/delete
├── tests.py           # 14-test suite (unit + integration)
├── requirements.txt
└── README.md
```

---

## ⚡ Quick Start

```bash
# Install dependency
pip install cryptography

# Start the server
python server.py

# Upload a file (encrypts locally before sending)
python client.py upload secret.pdf --password hunter2

# List stored files
python client.py list

# Download and decrypt
python client.py download secret.pdf --password hunter2 --out ~/Downloads

# Delete from vault
python client.py delete secret.pdf
```

---

## 🧪 Run Tests

```bash
python tests.py
```

```
test_exact_chunk              ... ok
test_large_file               ... ok
test_multi_chunk              ... ok
test_small_file               ... ok
test_tamper_detection         ... ok
test_deterministic            ... ok
test_different_passwords      ... ok
test_different_salts          ... ok
test_roundtrip_empty          ... ok
test_roundtrip_large          ... ok
test_roundtrip_small          ... ok
test_tamper_detection         ... ok
test_wrong_key                ... ok
test_upload_download_delete   ... ok

Ran 14 tests in 10.987s — OK
```

---

## 🖥️ CLI Reference

```bash
# Upload
python client.py upload <file> --password <pass> [--host HOST] [--port PORT]

# Download
python client.py download <filename> --password <pass> [--out DIR]

# List
python client.py list [--host HOST] [--port PORT]

# Delete
python client.py delete <filename>
```

Default server: `127.0.0.1:9999`

---

## 📡 Wire Protocol

Each message frame:
```
[4-byte big-endian header length] [JSON header] [binary payload]
```

The JSON header carries the command, metadata, and `payload_size`. Payload is the raw encrypted blob. No plaintext data ever appears in the header or payload on the wire.

---

## ⚙️ Dependencies

```
cryptography >= 42.0.0
```

Standard library only beyond that (`socket`, `threading`, `hashlib`, `struct`, `argparse`).

---

## 📄 License

MIT License — see [LICENSE](LICENSE)

---

<div align="center">
  <p>Built by <a href="https://github.com/AryanWaghere24">Aryan Waghere</a></p>
  <p>If this was useful, drop a ⭐ on the repo!</p>
</div>
