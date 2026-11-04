"""Discovery and isolated loading of optional application adapters.

* Adapters are found through the `bonelia.adapters` entry-point group — the core
  contains no reference to any specific application.
* A missing, broken or misconfigured adapter never prevents the server from
  starting; it is reported with a status instead.
* An adapter receives only its own configuration section and only the secret
  environment variables it declared (prefix `BONELIA_<ADAPTER_ID>_`).
* Adapter tools are namespaced, start disabled and can never be level 3.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from importlib.metadata import entry_points
from typing import Any, Iterable, Mapping

from ..contracts import RiskLevel
from ..repair.tools import ToolRegistry, ToolSpec
from .base import AdapterManifest, ServerAdapter

log = logging.getLogger("bonelia.adapters")

ENTRY_POINT_GROUP = "bonelia.adapters"
ADAPTER_ID = re.compile(r"^[a-z0-9][a-z0-9-]{1,40}$")


@dataclass
class LoadedAdapter:
    adapter_id: str
    status: str  # available | not_configured | disabled | load_error | invalid
    manifest: AdapterManifest | None = None
    instance: ServerAdapter | None = None
    tenant_ids: set[str] = field(default_factory=set)
    error: str | None = None
    tool_ids: list[str] = field(default_factory=list)

    def public(self, tenant_id: str | None = None) -> dict[str, Any]:
        d = self.manifest.to_dict() if self.manifest else {"adapter_id": self.adapter_id}
        d.pop("secret_env", None)
        d["load_status"] = self.status
        if tenant_id is not None:
            d["assigned_to_tenant"] = tenant_id in self.tenant_ids
        return d


def secret_prefix(adapter_id: str) -> str:
    return "BONELIA_" + adapter_id.upper().replace("-", "_") + "_"


def discover() -> list[Any]:
    try:
        return list(entry_points(group=ENTRY_POINT_GROUP))
    except Exception as exc:  # broken metadata must not stop the server
        log.warning("adapter discovery failed: %s", exc)
        return []


def _scoped_env(manifest: AdapterManifest, env: Mapping[str, str]) -> dict[str, str]:
    prefix = secret_prefix(manifest.adapter_id)
    return {k: env[k] for k in manifest.secret_env if k.startswith(prefix) and k in env}


def load_server_adapters(sections: Mapping[str, Mapping[str, Any]], env: Mapping[str, str],
                         eps: Iterable[Any] | None = None) -> dict[str, LoadedAdapter]:
    out: dict[str, LoadedAdapter] = {}
    for ep in (discover() if eps is None else eps):
        name = str(getattr(ep, "name", "?"))
        if not ADAPTER_ID.match(name) or name in out:
            out.setdefault(name, LoadedAdapter(name, "invalid", error="invalid_or_duplicate_id"))
            continue
        try:
            plugin = ep.load()
            manifest: AdapterManifest = plugin.manifest
            if manifest.adapter_id != name:
                raise ValueError("manifest id does not match entry point name")
        except Exception as exc:
            log.warning("adapter %s failed to load: %s", name, exc)
            out[name] = LoadedAdapter(name, "load_error", error=type(exc).__name__)
            continue
        section = dict(sections.get(name) or {})
        tenants = {str(t) for t in section.pop("tenant_ids", []) or []}
        if not section.pop("enabled", False):
            out[name] = LoadedAdapter(name, "disabled", manifest, tenant_ids=tenants)
            continue
        try:
            instance = plugin.create(section, _scoped_env(manifest, env))
        except Exception as exc:
            log.warning("adapter %s failed to initialise: %s", name, exc)
            out[name] = LoadedAdapter(name, "load_error", manifest, tenant_ids=tenants, error=type(exc).__name__)
            continue
        if instance is None:
            out[name] = LoadedAdapter(name, "not_configured", manifest, tenant_ids=tenants)
            continue
        out[name] = LoadedAdapter(name, "available", manifest, instance, tenants)
    return out


def register_adapter_tools(adapters: Mapping[str, LoadedAdapter], registry: ToolRegistry, enabled: set[str]) -> None:
    for la in adapters.values():
        if la.status != "available" or la.instance is None:
            continue
        try:
            specs = list(la.instance.tools())
        except Exception as exc:
            log.warning("adapter %s tools() failed: %s", la.adapter_id, exc)
            continue
        for spec in specs:
            if not isinstance(spec, ToolSpec) or not spec.tool_id.startswith(la.adapter_id + "."):
                log.warning("adapter %s offered a tool outside its namespace — rejected", la.adapter_id)
                continue
            if spec.risk_level >= RiskLevel.CRITICAL:
                log.warning("adapter %s offered a level-3 tool %s — rejected", la.adapter_id, spec.tool_id)
                continue
            spec.enabled = spec.tool_id in enabled
            try:
                registry.register(spec)
            except ValueError as exc:
                log.warning("tool %s rejected: %s", spec.tool_id, exc)
                continue
            la.tool_ids.append(spec.tool_id)


def adapter_of_tool(adapters: Mapping[str, LoadedAdapter], tool_id: str) -> LoadedAdapter | None:
    return next((la for la in adapters.values() if tool_id in la.tool_ids), None)
