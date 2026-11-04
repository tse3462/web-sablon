"""Generic Windows adapter — baseline diagnostics for ANY application, including
ones BONELİA AI has never seen. It uses only OS-level metadata and logs; it does
not open an application's own data files.
"""

from __future__ import annotations

from ..contracts import AppIdentity
from .base import Adapter, AdapterManifest

MANIFEST = AdapterManifest(
    adapter_id="generic-windows",
    name="Generic Windows",
    version="0.1.0",
    status="implemented",
    runs_on="client",
    capabilities={
        "recognize": True, "version_check": True, "find_logs": True, "api_connection": False,
        "health_check": True, "read_only_ops": True, "safe_interventions": False, "intervention_verification": False,
    },
    supported_app_versions="Windows 10/11, Windows Server 2016+",
    required_permissions=["Read Application/System event logs (standard user is usually sufficient)"],
    notes=("Internal business records (accounting, stock, orders) are NOT readable with this adapter; "
           "that requires an authorised application adapter."),
)


class GenericWindowsAdapter(Adapter):
    manifest = MANIFEST

    def recognize(self, apps: list[AppIdentity]) -> list[AppIdentity]:
        return [a.model_copy(update={"adapter_id": "generic-windows"}) for a in apps]


def filter_apps(apps: list[AppIdentity], query: str) -> list[AppIdentity]:
    q = query.lower().strip()
    return [a for a in apps if q in a.name.lower() or q in (a.publisher or "").lower()]
