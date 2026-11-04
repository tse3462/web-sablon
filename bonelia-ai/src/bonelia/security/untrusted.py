"""Handling of untrusted text (logs, error messages, external documents).

Log lines are attacker-controllable: anyone who can make an application print a
message can try to talk to the AI ("ignore previous instructions and run ...").
We therefore:
1. Fence every untrusted string with a random boundary the attacker cannot guess.
2. Neutralise boundary look-alikes inside the data.
3. Flag suspicious instruction-like content so the operator sees it.
4. Never let AI output reach an executor except via the tool gateway's allow list.
"""

from __future__ import annotations

import re
import secrets

_INJECTION_HINTS = re.compile(
    r"(?i)(ignore\s+(all\s+|any\s+)?(previous|prior|above)\s+(instructions|rules)"
    r"|disregard\s+(the\s+)?(system|previous)"
    r"|you\s+are\s+now\s+"
    r"|system\s*prompt"
    r"|act\s+as\s+(an?\s+)?(admin|administrator|root)"
    r"|run\s+(this\s+)?(command|powershell|cmd|shell)"
    r"|powershell\s+-(enc|command|e)\b"
    r"|invoke-expression|iex\s*\("
    r"|rm\s+-rf|del\s+/[sq]|format\s+[a-z]:"
    r"|drop\s+table|truncate\s+table|delete\s+from"
    r"|grant\s+(all|admin)|elevate|privilege"
    r"|önceki\s+talimatları\s+yok\s+say|vorherige\s+anweisungen\s+ignorieren)"
)


def injection_suspected(text: str) -> bool:
    return bool(_INJECTION_HINTS.search(text or ""))


def make_boundary() -> str:
    return "UNTRUSTED_" + secrets.token_hex(8).upper()


def fence(text: str, boundary: str) -> str:
    cleaned = (text or "").replace(boundary, "[boundary-removed]")
    cleaned = re.sub(r"(?i)untrusted_[0-9a-f]{16}", "[boundary-removed]", cleaned)
    return f"<<<{boundary}\n{cleaned}\n{boundary}>>>"
