"""Universal application recognition (works for software BONELİA AI has never seen).

Links error events (which usually only carry an executable or provider name) to
the installed-programs inventory, so the report shows the real product name,
publisher and installed version — without any application-specific code and
without opening any application data files.
"""

from __future__ import annotations

import re

from ..contracts import AppIdentity, DiagnosticEvent

_SUFFIX = re.compile(r"\.(exe|dll|com|msi)$", re.I)
_NOISE = re.compile(r"\b(x64|x86|64-bit|32-bit|version|v?\d+(\.\d+)*)\b", re.I)


def normalize(name: str) -> str:
    n = _SUFFIX.sub("", (name or "").strip().lower())
    n = _NOISE.sub(" ", n)
    return re.sub(r"[^a-z0-9]+", "", n)


def match_installed(event_app_name: str, installed: list[AppIdentity]) -> AppIdentity | None:
    """Best match by normalised name: exact > prefix > containment (min. 4 chars)."""
    key = normalize(event_app_name)
    if len(key) < 4:
        return None
    best: tuple[int, AppIdentity] | None = None
    for app in installed:
        cand = normalize(app.name)
        if not cand:
            continue
        if cand == key:
            score = 3
        elif cand.startswith(key) or key.startswith(cand) and len(cand) >= 4:
            score = 2
        elif key in cand:
            score = 1
        else:
            continue
        if best is None or score > best[0] or (score == best[0] and len(cand) < len(normalize(best[1].name))):
            best = (score, app)
    return best[1] if best else None


def correlate(events: list[DiagnosticEvent], installed: list[AppIdentity]) -> list[DiagnosticEvent]:
    """Enrich events in place with installed product name, publisher and version."""
    if not installed:
        return events
    for ev in events:
        if ev.app.adapter_id != "generic-windows" or not ev.app.app_id.startswith("win:"):
            continue
        hit = match_installed(ev.app.name, installed)
        if hit is None:
            continue
        ev.app = ev.app.model_copy(update={
            "publisher": ev.app.publisher or hit.publisher,
            "version": ev.app.version or hit.version,
            "name": ev.app.name if ev.app.name.lower() == hit.name.lower() else f"{hit.name} ({ev.app.name})"[:200],
        })
    return events
