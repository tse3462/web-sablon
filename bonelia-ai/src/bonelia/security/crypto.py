"""Device identity, request signing and encrypted local storage.

Design (see docs/THREAT_MODEL.md):
* Every USB copy generates its OWN Ed25519 key pair at enrollment. The server only
  stores the public key, bound to one tenant and a scope list. Losing one USB never
  exposes other devices; the device is revoked server-side.
* The private key is stored on the USB encrypted with a passphrase-derived key
  (scrypt -> AES-256-GCM). No plaintext secrets are written to removable media.
* Each request is signed over method, path, timestamp, nonce and body hash. The
  server rejects stale timestamps and replayed nonces.
* Each response is signed with the server key; the client pins the server public
  key received at enrollment, so a fake server cannot impersonate the real one.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

SIGNATURE_MAX_SKEW_S = 300

H_DEVICE = "X-Bonelia-Device"
H_TS = "X-Bonelia-Timestamp"
H_NONCE = "X-Bonelia-Nonce"
H_SIG = "X-Bonelia-Signature"
H_SERVER_SIG = "X-Bonelia-Server-Signature"


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"), validate=True)


# --------------------------------------------------------------------------- keys


def generate_keypair() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def public_key_b64(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return b64e(raw)


def load_public_key(b64: str) -> Ed25519PublicKey:
    raw = b64d(b64)
    if len(raw) != 32:
        raise ValueError("invalid public key length")
    return Ed25519PublicKey.from_public_bytes(raw)


def private_key_bytes(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())


def load_private_key(raw: bytes) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(raw)


# --------------------------------------------------------------------------- signing


def canonical_request(method: str, path: str, ts: str, nonce: str, body: bytes) -> bytes:
    body_hash = hashlib.sha256(body).hexdigest()
    return "\n".join(["BONELIA-V1", method.upper(), path, ts, nonce, body_hash]).encode("utf-8")


def sign_request(key: Ed25519PrivateKey, device_id: str, method: str, path: str, body: bytes) -> dict[str, str]:
    ts = str(int(time.time()))
    nonce = secrets.token_hex(16)
    sig = key.sign(canonical_request(method, path, ts, nonce, body))
    return {H_DEVICE: device_id, H_TS: ts, H_NONCE: nonce, H_SIG: b64e(sig)}


def verify_request(pub: Ed25519PublicKey, method: str, path: str, ts: str, nonce: str, body: bytes, sig_b64: str,
                   now: float | None = None) -> None:
    """Raise ValueError if the signature or timestamp is not acceptable."""
    try:
        ts_i = int(ts)
    except (TypeError, ValueError) as exc:
        raise ValueError("bad timestamp") from exc
    current = time.time() if now is None else now
    if abs(current - ts_i) > SIGNATURE_MAX_SKEW_S:
        raise ValueError("stale timestamp")
    if not nonce or len(nonce) > 64:
        raise ValueError("bad nonce")
    try:
        pub.verify(b64d(sig_b64), canonical_request(method, path, ts, nonce, body))
    except (InvalidSignature, ValueError) as exc:
        raise ValueError("bad signature") from exc


def canonical_response(status: int, nonce: str, body: bytes) -> bytes:
    return "\n".join(["BONELIA-RESP-V1", str(status), nonce, hashlib.sha256(body).hexdigest()]).encode("utf-8")


def sign_response(key: Ed25519PrivateKey, status: int, request_nonce: str, body: bytes) -> str:
    return b64e(key.sign(canonical_response(status, request_nonce, body)))


def verify_response(pub: Ed25519PublicKey, status: int, request_nonce: str, body: bytes, sig_b64: str | None) -> None:
    if not sig_b64:
        raise ValueError("missing server signature")
    try:
        pub.verify(b64d(sig_b64), canonical_response(status, request_nonce, body))
    except (InvalidSignature, ValueError) as exc:
        raise ValueError("server signature invalid — possible fake server") from exc


# --------------------------------------------------------------------------- encrypted storage

_SCRYPT_N = 2**15
_SCRYPT_R = 8
_SCRYPT_P = 1


def _derive(passphrase: str, salt: bytes) -> bytes:
    if len(passphrase) < 10:
        raise ValueError("passphrase must have at least 10 characters")
    return Scrypt(salt=salt, length=32, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P).derive(passphrase.encode("utf-8"))


def encrypt_blob(plaintext: bytes, passphrase: str, aad: bytes = b"bonelia-v1") -> bytes:
    salt = os.urandom(16)
    nonce = os.urandom(12)
    ct = AESGCM(_derive(passphrase, salt)).encrypt(nonce, plaintext, aad)
    envelope = {"v": 1, "kdf": "scrypt", "n": _SCRYPT_N, "salt": b64e(salt), "nonce": b64e(nonce), "ct": b64e(ct)}
    return json.dumps(envelope).encode("utf-8")


def decrypt_blob(blob: bytes, passphrase: str, aad: bytes = b"bonelia-v1") -> bytes:
    try:
        env = json.loads(blob.decode("utf-8"))
        if env.get("v") != 1 or env.get("kdf") != "scrypt":
            raise ValueError("unsupported envelope")
        key = _derive(passphrase, b64d(env["salt"]))
        return AESGCM(key).decrypt(b64d(env["nonce"]), b64d(env["ct"]), aad)
    except InvalidTag as exc:
        raise ValueError("wrong passphrase or corrupted data") from exc
    except (KeyError, json.JSONDecodeError) as exc:
        raise ValueError("corrupted envelope") from exc


class DataKey:
    """Symmetric key for bulk data (reports, offline queue) once the vault is unlocked."""

    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("data key must be 32 bytes")
        self._aes = AESGCM(key)

    def encrypt(self, data: bytes, aad: bytes = b"bonelia-data") -> bytes:
        nonce = os.urandom(12)
        return b"BDK1" + nonce + self._aes.encrypt(nonce, data, aad)

    def decrypt(self, blob: bytes, aad: bytes = b"bonelia-data") -> bytes:
        if not blob.startswith(b"BDK1"):
            raise ValueError("not a BONELIA data blob")
        try:
            return self._aes.decrypt(blob[4:16], blob[16:], aad)
        except InvalidTag as exc:
            raise ValueError("corrupted data") from exc


@dataclass
class DeviceCredentials:
    server_url: str
    device_id: str
    tenant_id: str
    scopes: list[str]
    server_public_key_b64: str
    private_key: Ed25519PrivateKey
    data_key: bytes

    def to_json(self) -> bytes:
        return json.dumps({
            "server_url": self.server_url,
            "device_id": self.device_id,
            "tenant_id": self.tenant_id,
            "scopes": self.scopes,
            "server_public_key_b64": self.server_public_key_b64,
            "private_key_b64": b64e(private_key_bytes(self.private_key)),
            "data_key_b64": b64e(self.data_key),
        }).encode("utf-8")

    @classmethod
    def from_json(cls, raw: bytes) -> "DeviceCredentials":
        d = json.loads(raw.decode("utf-8"))
        return cls(
            server_url=d["server_url"], device_id=d["device_id"], tenant_id=d["tenant_id"], scopes=list(d["scopes"]),
            server_public_key_b64=d["server_public_key_b64"],
            private_key=load_private_key(b64d(d["private_key_b64"])), data_key=b64d(d["data_key_b64"]),
        )


class Vault:
    """Encrypted credential file on the USB stick (`config/device.vault`)."""

    def __init__(self, path: Path):
        self.path = path

    def exists(self) -> bool:
        return self.path.is_file()

    def save(self, creds: DeviceCredentials, passphrase: str) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_bytes(encrypt_blob(creds.to_json(), passphrase, aad=b"bonelia-vault-v1"))
        os.replace(tmp, self.path)

    def load(self, passphrase: str) -> DeviceCredentials:
        return DeviceCredentials.from_json(decrypt_blob(self.path.read_bytes(), passphrase, aad=b"bonelia-vault-v1"))


def hash_secret(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def constant_time_equal(a: str, b: str) -> bool:
    return secrets.compare_digest(a.encode("utf-8"), b.encode("utf-8"))
