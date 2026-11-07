"""Settings of the "brain" (Claude for important problems, user request 07.11.2026).

Kept in the server's settings table: {"enabled", "monthly_limit", "model"} under "brain" and the API key under
"anthropic_api_key" (on this PC only; the panel never shows it again). Customer consent is the tenant's
cloud_ai_allowed flag. The router asks `current()` on every analysis, so a change in the panel takes effect at once.
"""

from __future__ import annotations

import re
from typing import Any

from ..ai.claude import DEFAULT_MODEL, MODELS, ClaudeProvider

SETTINGS_KEY = "brain"
KEY_SETTING = "anthropic_api_key"
DEFAULT_LIMIT = 5.0
MAX_LIMIT = 200.0
KEY_RE = re.compile(r"^sk-ant-[A-Za-z0-9_\-]{20,200}$")


def make_provider(key: str, model: str) -> Any:
    return ClaudeProvider(key, model=model)


def settings(store) -> dict[str, Any]:
    raw = store.get_setting(SETTINGS_KEY)
    raw = raw if isinstance(raw, dict) else {}
    limit = raw.get("monthly_limit")
    return {"enabled": raw.get("enabled") is True,
            "monthly_limit": float(limit) if isinstance(limit, (int, float)) and 0 < limit <= MAX_LIMIT else DEFAULT_LIMIT,
            "model": raw.get("model") if raw.get("model") in MODELS else DEFAULT_MODEL}


class Brain:
    def __init__(self, store):
        self.store = store
        self._cached: tuple[tuple[str, str], Any] | None = None

    def provider(self) -> Any | None:
        key = self.store.get_setting(KEY_SETTING)
        if not isinstance(key, str) or not KEY_RE.match(key):
            return None
        model = settings(self.store)["model"]
        if self._cached is None or self._cached[0] != (key, model):
            self._cached = ((key, model), make_provider(key, model))
        return self._cached[1]

    def current(self) -> tuple[Any, float] | None:
        """(provider, monthly limit) while the brain is switched on and a key is set, else None."""
        s = settings(self.store)
        if not s["enabled"]:
            return None
        p = self.provider()
        return (p, s["monthly_limit"]) if p is not None else None
