"""Encrypted blob storage. Each file gets its own random key (AES-256-GCM);
that key is wrapped with a master key that never touches the database."""
import hashlib
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from flask import current_app


def derive(secret: str, purpose: bytes) -> bytes:
    """Independent 32-byte keys from one secret (file master key, audit HMAC key, ...)."""
    return HKDF(algorithm=SHA256(), length=32, salt=None, info=purpose).derive(secret.encode())


def derive_master(secret: str) -> bytes:
    return derive(secret, b"trustvault-file-master")


def _path(doc_id, version):
    if not (isinstance(version, int) and version > 0):
        raise ValueError("bad version")
    # doc_id is always a validated UUID string from the database
    return os.path.join(current_app.config["BLOB_DIR"], f"{doc_id}.{version}.bin")


def save(doc_id, version, data: bytes) -> bytes:
    file_key, nonce, wnonce = os.urandom(32), os.urandom(12), os.urandom(12)
    ct = AESGCM(file_key).encrypt(nonce, data, doc_id.encode())
    fd = os.open(_path(doc_id, version), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(nonce + ct)
    master = current_app.config["_MASTER"]
    return wnonce + AESGCM(master).encrypt(wnonce, file_key, doc_id.encode())


def load(doc_id, version, wrapped: bytes) -> bytes:
    master = current_app.config["_MASTER"]
    file_key = AESGCM(master).decrypt(wrapped[:12], wrapped[12:], doc_id.encode())
    with open(_path(doc_id, version), "rb") as f:
        blob = f.read()
    return AESGCM(file_key).decrypt(blob[:12], blob[12:], doc_id.encode())


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
