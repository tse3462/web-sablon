"""Application adapters and the adapter manifest catalogue."""

from __future__ import annotations

import json
from importlib import resources

from .base import AdapterManifest
from .generic_windows import MANIFEST as GENERIC_MANIFEST
from .veedelkorb import MANIFEST as VEEDELKORB_MANIFEST


def planned_manifests() -> list[AdapterManifest]:
    """Adapters that are designed but NOT implemented yet (documented honestly)."""
    raw = resources.files("bonelia").joinpath("resources/planned_adapters.json").read_text(encoding="utf-8")
    return [AdapterManifest(**item) for item in json.loads(raw)]


def all_manifests() -> list[AdapterManifest]:
    return [GENERIC_MANIFEST, VEEDELKORB_MANIFEST, *planned_manifests()]
