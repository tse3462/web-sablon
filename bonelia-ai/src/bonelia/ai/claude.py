"""Claude as the "brain" of BONELIA AI (user request 07.11.2026).

Only important problems are sent here (the router decides); everything else stays on the free local model.
The key is entered once in the control panel and kept on the home server only. A decline (refusal) or any
API error raises ProviderError, so the router falls back to the local model / the rules -- the platform never
blocks on the cloud.
"""

from __future__ import annotations

import time
from typing import Any

from .costs import Price
from .providers import ProviderError, ProviderResult

MODELS = ("claude-opus-5-5", "claude-sonnet-5-5", "claude-haiku-5-5")
DEFAULT_MODEL = "claude-opus-5-5"
# Anthropic list prices per million tokens (USD; counted 1:1 against the EUR limit, which errs on the safe side).
# Check them against https://platform.claude.com/docs/en/about-claude/pricing when they change.
_PRICES = {"claude-opus-5-5": (4.0, 20.0), "claude-sonnet-5-5": (2.0, 10.0), "claude-haiku-5-5": (0.10, 0.50)}
# Models with Anthropic's server-side refusal fallback ("default" routes by refusal category).
_FALLBACK_MODELS = {"claude-opus-5-5", "claude-sonnet-5-5"}


def claude_prices() -> dict[str, Price]:
    return {f"anthropic:{m}": Price(i, o, "USD") for m, (i, o) in _PRICES.items()}


class ClaudeProvider:
    is_cloud = True
    name = "anthropic"

    def __init__(self, api_key: str, model: str = DEFAULT_MODEL, effort: str = "medium", client: Any = None,
                 timeout_s: float = 180.0):
        if not api_key:
            raise ValueError("Claude needs an API key (entered in the control panel)")
        self.model = model if model in MODELS else DEFAULT_MODEL
        self.effort = effort
        if client is None:
            import anthropic

            client = anthropic.Anthropic(api_key=api_key, timeout=timeout_s, max_retries=2)
        self._client = client

    def available(self) -> bool:
        return True  # checked on use; a failure falls back to the local model / rules

    def complete(self, system: str, user: str, max_output_tokens: int = 900) -> ProviderResult:
        import anthropic

        t0 = time.monotonic()
        # Thinking is adaptive on these models (on by default); the answer must still leave room after it.
        kw: dict[str, Any] = {"model": self.model, "max_tokens": max(8000, max_output_tokens), "system": system,
                              "messages": [{"role": "user", "content": user}], "output_config": {"effort": self.effort}}
        if self.model in _FALLBACK_MODELS:
            kw.update(betas=["server-side-fallback-2026-07-01"], fallbacks="default")
        try:
            msg = self._client.beta.messages.create(**kw)
        except anthropic.APIError as exc:
            raise ProviderError(f"anthropic: {type(exc).__name__}") from exc
        if getattr(msg, "stop_reason", None) == "refusal":
            raise ProviderError("anthropic: refusal")
        text = "".join(b.text for b in (msg.content or []) if getattr(b, "type", "") == "text")
        if not text.strip():
            raise ProviderError("anthropic: empty answer")
        usage = getattr(msg, "usage", None)
        return ProviderResult(text=text, input_tokens=int(getattr(usage, "input_tokens", 0) or 0),
                              output_tokens=int(getattr(usage, "output_tokens", 0) or 0),
                              latency_ms=int((time.monotonic() - t0) * 1000), model=self.model)
