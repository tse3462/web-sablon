"""Application adapters.

Only the universal `generic-windows` adapter lives in the core. Application-specific
adapters are optional packages discovered at runtime (see `registry.py`).
"""

from __future__ import annotations

import json
from importlib import resources

from .base import AdapterManifest
from .generic_windows import MANIFEST as GENERIC_MANIFEST


def planned_manifests() -> list[AdapterManifest]:
    """Adapters that are designed but NOT implemented yet (documented honestly)."""
    raw = resources.files("bonelia").joinpath("resources/planned_adapters.json").read_text(encoding="utf-8")
    return [AdapterManifest(**item) for item in json.loads(raw)]


def core_manifests() -> list[AdapterManifest]:
    return [GENERIC_MANIFEST, *planned_manifests()]
