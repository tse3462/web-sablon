"""AI provider connectors. Swapping a model never requires changing the USB client:
providers live only on the server and are selected by configuration.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Protocol

import httpx


class ProviderError(RuntimeError):
    pass


@dataclass
class ProviderResult:
    text: str
    input_tokens: int
    output_tokens: int
    latency_ms: int
    model: str


class Provider(Protocol):
    name: str  # "ollama" | "openai" | ...
    model: str
    is_cloud: bool

    def available(self) -> bool: ...

    def complete(self, system: str, user: str, max_output_tokens: int = 900) -> ProviderResult: ...


class OllamaProvider:
    """Local model served by Ollama (https://github.com/ollama/ollama, /api/chat)."""

    is_cloud = False
    name = "ollama"

    def __init__(self, base_url: str = "http://127.0.0.1:11434", model: str = "qwen2.5:7b-instruct",
                 timeout_s: float = 120.0, transport: httpx.BaseTransport | None = None):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self._client = httpx.Client(timeout=httpx.Timeout(timeout_s, connect=5.0), transport=transport)

    def available(self) -> bool:
        try:
            r = self._client.get(f"{self.base_url}/api/tags", timeout=3.0)
            if r.status_code != 200:
                return False
            names = {m.get("name") for m in r.json().get("models", [])}
            return self.model in names or f"{self.model}:latest" in names
        except (httpx.HTTPError, ValueError):
            return False

    def complete(self, system: str, user: str, max_output_tokens: int = 900) -> ProviderResult:
        t0 = time.monotonic()
        try:
            r = self._client.post(f"{self.base_url}/api/chat", json={
                "model": self.model,
                "stream": False,
                "format": "json",
                "options": {"temperature": 0.1, "num_predict": max_output_tokens},
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            })
            r.raise_for_status()
            body = r.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise ProviderError(f"ollama: {type(exc).__name__}") from exc
        return ProviderResult(
            text=str(body.get("message", {}).get("content", "")),
            input_tokens=int(body.get("prompt_eval_count") or 0),
            output_tokens=int(body.get("eval_count") or 0),
            latency_ms=int((time.monotonic() - t0) * 1000),
            model=self.model,
        )


class OpenAICompatibleProvider:
    """OpenAI Chat Completions API (or a compatible endpoint). Key is read on the server only."""

    is_cloud = True

    def __init__(self, api_key: str, model: str, base_url: str = "https://api.openai.com/v1", name: str = "openai",
                 timeout_s: float = 60.0, transport: httpx.BaseTransport | None = None):
        if not api_key:
            raise ValueError("cloud provider requires an API key (server-side environment variable)")
        self.name = name
        self.model = model
        self.base_url = base_url.rstrip("/")
        self._client = httpx.Client(timeout=httpx.Timeout(timeout_s, connect=5.0), transport=transport,
                                    headers={"Authorization": f"Bearer {api_key}"})

    def available(self) -> bool:
        return True  # checked lazily on first call; failures fall back to rules

    def complete(self, system: str, user: str, max_output_tokens: int = 900) -> ProviderResult:
        t0 = time.monotonic()
        try:
            r = self._client.post(f"{self.base_url}/chat/completions", json={
                "model": self.model,
                "temperature": 0.1,
                "max_tokens": max_output_tokens,
                "response_format": {"type": "json_object"},
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            })
            r.raise_for_status()
            body = r.json()
            text = body["choices"][0]["message"]["content"] or ""
        except (httpx.HTTPError, ValueError, KeyError, IndexError) as exc:
            raise ProviderError(f"{self.name}: {type(exc).__name__}") from exc
        usage = body.get("usage") or {}
        return ProviderResult(text=text, input_tokens=int(usage.get("prompt_tokens") or 0),
                              output_tokens=int(usage.get("completion_tokens") or 0),
                              latency_ms=int((time.monotonic() - t0) * 1000), model=self.model)
