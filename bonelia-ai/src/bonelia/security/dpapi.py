"""Windows DPAPI (CryptProtectData) for the unattended agent's credentials.

The agent cannot ask for a passphrase. Its device key is therefore protected with
DPAPI in *machine* scope and stored under %ProgramData% with an ACL limited to
SYSTEM and Administrators. Copied to another PC, the file is useless.
"""

from __future__ import annotations

import sys

CRYPTPROTECT_UI_FORBIDDEN = 0x01
CRYPTPROTECT_LOCAL_MACHINE = 0x04
_ENTROPY = b"BONELIA-AI-agent-v1"


def available() -> bool:
    return sys.platform == "win32"


def _call(fn_name: str, data: bytes, flags: int) -> bytes:
    import ctypes
    from ctypes import wintypes

    class BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    def blob(b: bytes) -> BLOB:
        buf = ctypes.create_string_buffer(b, len(b))
        return BLOB(len(b), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))

    crypt32, kernel32 = ctypes.windll.crypt32, ctypes.windll.kernel32  # type: ignore[attr-defined]
    src, ent, out = blob(data), blob(_ENTROPY), BLOB()
    fn = getattr(crypt32, fn_name)
    if fn_name == "CryptProtectData":
        ok = fn(ctypes.byref(src), "BONELIA AI agent", ctypes.byref(ent), None, None, flags, ctypes.byref(out))
    else:
        ok = fn(ctypes.byref(src), None, ctypes.byref(ent), None, None, flags, ctypes.byref(out))
    if not ok:
        raise OSError(f"{fn_name} failed: {ctypes.GetLastError()}")
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        kernel32.LocalFree(out.pbData)


def protect(data: bytes) -> bytes:
    if not available():
        raise OSError("DPAPI is only available on Windows")
    return _call("CryptProtectData", data, CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE)


def unprotect(data: bytes) -> bytes:
    if not available():
        raise OSError("DPAPI is only available on Windows")
    return _call("CryptUnprotectData", data, CRYPTPROTECT_UI_FORBIDDEN)
