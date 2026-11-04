"""Personal-data and secret redaction (data minimisation, GDPR/DSGVO Art. 5(1)(c)).

Every piece of evidence passes through `redact_text` before it leaves the customer
machine or reaches any AI model. The rules are intentionally aggressive: a false
positive costs a little diagnostic detail, a false negative leaks personal data.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

# Order matters: secrets first (they may contain e-mail-like or numeric fragments).
_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), "[private-key]"),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), "[jwt]"),
    ("bearer", re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"), r"\1 [secret]"),
    ("api_key", re.compile(r"\b(sk|pk|rk)[-_](live|test|proj)?[-_]?[A-Za-z0-9]{16,}\b"), "[api-key]"),
    ("kv_secret", re.compile(r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|apikey|client[_-]?secret|connectionstring)\s*[=:]\s*([^\s;,'\"]+)"), r"\1=[secret]"),
    ("conn_userinfo", re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@"), r"\1[credentials]@"),
    ("email", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "[email]"),
    ("iban", re.compile(r"\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){3,7}(?:\s?[A-Z0-9]{1,3})?\b"), "[iban]"),
    ("card", re.compile(r"\b(?:\d[ -]?){13,19}\b"), "[card-or-number]"),
    ("uuid", re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"), "[uuid]"),
    ("mac", re.compile(r"\b[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}\b"), "[mac]"),
    ("ipv4", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"), "[ip]"),
    ("phone", re.compile(r"(?<![\w.])(?:\+\d{1,3}|00\d{1,3}|0\d{2,5})[ /.-]?\(?\d{2,5}\)?[ /.-]?\d{3,}(?:[ /.-]?\d{2,})?(?![\w.])"), "[phone]"),
    ("win_user_path", re.compile(r"(?i)([a-z]:\\users\\)[^\\\s]+"), r"\1[user]"),
    ("unix_home", re.compile(r"(/home/|/Users/)[^/\s]+"), r"\1[user]"),
    ("query_string", re.compile(r"\?[^\s#)\"']+"), "?[redacted]"),
    ("long_number", re.compile(r"\b\d{6,}\b"), "[number]"),
]

_MAX_TEXT = 4000


def redact_text(value: str | None, limit: int = _MAX_TEXT) -> str:
    if not value:
        return ""
    text = value[: limit * 3]
    for _, pattern, repl in _PATTERNS:
        text = pattern.sub(repl, text)
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", " ", text)
    return text[:limit]


def redact_value(value: Any, depth: int = 0) -> Any:
    """Recursively redact strings inside JSON-like structures."""
    if depth > 6:
        return "[truncated]"
    if isinstance(value, str):
        return redact_text(value, 1000)
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in list(value.items())[:100]:
            key = str(k)[:80]
            if re.search(r"(?i)pass|secret|token|key|credential|auth", key):
                out[key] = "[secret]"
            else:
                out[key] = redact_value(v, depth + 1)
        return out
    if isinstance(value, (list, tuple)):
        return [redact_value(v, depth + 1) for v in list(value)[:100]]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return redact_text(str(value), 200)


def pseudonymize(value: str, salt: str) -> str:
    """Stable, non-reversible reference (e.g. for hostnames)."""
    return "ref_" + hashlib.sha256((salt + "|" + value).encode("utf-8")).hexdigest()[:16]


def contains_pii(value: str) -> list[str]:
    """Return the names of redaction rules that would fire (used in tests/audits)."""
    return [name for name, pattern, _ in _PATTERNS if pattern.search(value or "")]
