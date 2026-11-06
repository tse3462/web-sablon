"""Password vault, Python side (user request 06.11.2026). Must match web/vault/entry.js.

The vault is an X25519 key pair. Its private key is wrapped with AES-256-GCM under scrypt(master password)
and is only ever unwrapped on the owner's phone. The server stores the public key, the wrapped private key
and sealed entries, none of which can be read without the master password.

An entry is a sealed box to the vault's public key: an ephemeral X25519 key, HKDF-SHA256 over the shared
secret, AES-256-GCM. Agents use ``seal`` to hand over a new RustDesk password they just set, so a readable
password exists only in RustDesk itself and, after unlocking, on the owner's phone.

``create`` and ``unlock`` exist for tests and tools; the panel does this in the browser.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import secrets
import unicodedata
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

KEY_AAD = "bonelia-vault-key-v1|"
BOX_INFO = b"bonelia-vault-box-v1"
KDF = {"n": 32768, "r": 8, "p": 1}
_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _unb64(s: Any, size: int | None = None, max_size: int = 4096) -> bytes:
    if not isinstance(s, str) or len(s) > max_size * 2:
        raise ValueError("bad_b64")
    try:
        b = base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("bad_b64") from exc
    if (size is not None and len(b) != size) or len(b) > max_size:
        raise ValueError("bad_size")
    return b


def _raw(pub: X25519PublicKey) -> bytes:
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _box_key(shared: bytes, epk: bytes, pub: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=epk + pub, info=BOX_INFO).derive(shared)


def valid_public_key(pub_b64: Any) -> bool:
    try:
        _unb64(pub_b64, 32)
        return True
    except ValueError:
        return False


def valid_box(box: Any) -> bool:
    """Shape check the server does before storing a sealed entry (it cannot and need not read it)."""
    try:
        return (isinstance(box, dict) and box.get("v") == 1 and set(box) == {"v", "epk", "nonce", "ct"}
                and bool(_unb64(box["epk"], 32)) and bool(_unb64(box["nonce"], 12)) and 16 < len(_unb64(box["ct"])) <= 4096)
    except ValueError:
        return False


def valid_meta(meta: Any) -> bool:
    try:
        kdf = meta["kdf"]
        return (meta.get("v") == 1 and kdf.get("alg") == "scrypt" and kdf.get("n") in (16384, 32768, 65536)
                and kdf.get("r") == 8 and kdf.get("p") == 1 and bool(_unb64(kdf["salt"], 16))
                and valid_public_key(meta["pub"]) and bool(_unb64(meta["wrap"]["nonce"], 12))
                and len(_unb64(meta["wrap"]["ct"])) == 48)
    except (KeyError, TypeError, AttributeError, ValueError):
        return False


def seal(pub_b64: str, payload: dict[str, Any]) -> dict[str, Any]:
    pub = _unb64(pub_b64, 32)
    eph = X25519PrivateKey.generate()
    epk = _raw(eph.public_key())
    shared = eph.exchange(X25519PublicKey.from_public_bytes(pub))
    nonce = secrets.token_bytes(12)
    ct = AESGCM(_box_key(shared, epk, pub)).encrypt(nonce, json.dumps(payload).encode("utf-8"), BOX_INFO)
    return {"v": 1, "epk": _b64(epk), "nonce": _b64(nonce), "ct": _b64(ct)}


def open_box(priv: bytes, box: dict[str, Any]) -> dict[str, Any]:
    key = X25519PrivateKey.from_private_bytes(priv)
    epk = _unb64(box["epk"], 32)
    shared = key.exchange(X25519PublicKey.from_public_bytes(epk))
    pt = AESGCM(_box_key(shared, epk, _raw(key.public_key()))).decrypt(_unb64(box["nonce"], 12), _unb64(box["ct"]), BOX_INFO)
    return json.loads(pt.decode("utf-8"))


def _master_key(password: str, kdf: dict[str, Any]) -> bytes:
    return hashlib.scrypt(unicodedata.normalize("NFC", password).encode("utf-8"), salt=_unb64(kdf["salt"], 16),
                          n=kdf["n"], r=kdf["r"], p=kdf["p"], dklen=32, maxmem=256 * 1024 * 1024)


def create(password: str) -> dict[str, Any]:
    priv = X25519PrivateKey.generate()
    raw_priv = priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    pub_b64 = _b64(_raw(priv.public_key()))
    kdf = {"alg": "scrypt", **KDF, "salt": _b64(secrets.token_bytes(16))}
    nonce = secrets.token_bytes(12)
    ct = AESGCM(_master_key(password, kdf)).encrypt(nonce, raw_priv, (KEY_AAD + pub_b64).encode("utf-8"))
    return {"v": 1, "kdf": kdf, "pub": pub_b64, "wrap": {"nonce": _b64(nonce), "ct": _b64(ct)}}


def unlock(meta: dict[str, Any], password: str) -> bytes:
    from cryptography.exceptions import InvalidTag

    try:
        priv = AESGCM(_master_key(password, meta["kdf"])).decrypt(
            _unb64(meta["wrap"]["nonce"], 12), _unb64(meta["wrap"]["ct"]), (KEY_AAD + meta["pub"]).encode("utf-8"))
    except InvalidTag as exc:
        raise ValueError("wrong_password") from exc
    if _b64(_raw(X25519PrivateKey.from_private_bytes(priv).public_key())) != meta["pub"]:
        raise ValueError("wrong_password")
    return priv


def random_password(length: int = 16) -> str:
    """Letters and digits only (RustDesk accepts them on every command line), no look-alikes."""
    return "".join(secrets.choice(_ALPHABET) for _ in range(length))


def fingerprint(pub_b64: str) -> str:
    return hashlib.sha256(pub_b64.encode("ascii")).hexdigest()[:16]
