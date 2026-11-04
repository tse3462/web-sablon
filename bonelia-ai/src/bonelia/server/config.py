"""Server configuration. Secrets come ONLY from environment variables on the server."""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class ServerConfig:
    data_dir: Path
    host: str = "127.0.0.1"
    port: int = 8742
    tls_cert: Path | None = None
    tls_key: Path | None = None
    ollama_url: str | None = "http://127.0.0.1:11434"
    ollama_model: str = "qwen2.5:7b-instruct"
    cloud_provider: str | None = None  # "openai" or None
    cloud_model: str = "gpt-4o-mini"
    cloud_base_url: str = "https://api.openai.com/v1"
    prices: dict[str, Any] = field(default_factory=dict)
    max_concurrent_analyses: int = 2
    max_ai_events_per_request: int = 5
    # Optional adapter sections: {"<adapter_id>": {"enabled": bool, "tenant_ids": [...], ...adapter settings}}
    adapters: dict[str, dict[str, Any]] = field(default_factory=dict)
    enabled_tools: list[str] = field(default_factory=list)

    @property
    def db_path(self) -> Path:
        return self.data_dir / "bonelia.db"

    @property
    def key_path(self) -> Path:
        return self.data_dir / "server_ed25519.key"

    @staticmethod
    def env_secret(name: str) -> str | None:
        v = os.environ.get(name)
        return v if v else None

    @classmethod
    def load(cls, path: Path | None, data_dir: Path | None = None) -> "ServerConfig":
        raw: dict[str, Any] = {}
        if path and path.is_file():
            raw = tomllib.loads(path.read_text(encoding="utf-8"))
        server = raw.get("server", {})
        ai = raw.get("ai", {})
        dd = Path(data_dir or server.get("data_dir") or "./bonelia-server-data").resolve()
        return cls(
            data_dir=dd,
            host=server.get("host", "127.0.0.1"),
            port=int(server.get("port", 8742)),
            tls_cert=Path(server["tls_cert"]) if server.get("tls_cert") else None,
            tls_key=Path(server["tls_key"]) if server.get("tls_key") else None,
            ollama_url=ai.get("ollama_url", "http://127.0.0.1:11434") or None,
            ollama_model=ai.get("ollama_model", "qwen2.5:7b-instruct"),
            cloud_provider=ai.get("cloud_provider"),
            cloud_model=ai.get("cloud_model", "gpt-4o-mini"),
            cloud_base_url=ai.get("cloud_base_url", "https://api.openai.com/v1"),
            prices=ai.get("prices", {}),
            max_concurrent_analyses=int(server.get("max_concurrent_analyses", 2)),
            max_ai_events_per_request=int(ai.get("max_ai_events_per_request", 5)),
            adapters={k: dict(v) for k, v in (raw.get("adapters") or {}).items() if isinstance(v, dict)},
            enabled_tools=list(raw.get("repair", {}).get("enabled_tools", [])),
        )
