"""BONELİA AI Control Center (v0.1): local web panel on the home server.

Served on 127.0.0.1 only, random port, random per-launch token and strict Host
check (same protection as the USB UI). It reads the server database directly; it
is not reachable from the network.
"""

from __future__ import annotations

import ipaddress
import json
import os
import secrets
import socket
import threading
import webbrowser
from datetime import datetime, timedelta
from importlib import resources
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from .. import __version__
from ..contracts import Diagnosis, DiagnosticEvent, RiskLevel, utcnow
from ..repair.builtin_tools import SAFE_AUTO_TOOLS
from .store import Store

ONLINE_MINUTES = 15  # agents report every 5 minutes
_TAILSCALE = ipaddress.ip_network("100.64.0.0/10")


def is_safe_bind(host: str) -> bool:
    """Loopback is always fine; a Tailscale address (100.64/10, WireGuard-encrypted) is fine for phone access."""
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_loopback or ip in _TAILSCALE
    except ValueError:
        return host in ("localhost",) or host.endswith(".ts.net")


def _kind(scopes: list[str]) -> str:
    if "agent" in scopes:
        return "agent"
    if scopes == ["install:agent"]:
        return "install_key"
    return "usb"


class LevelBody(BaseModel):
    level: int = Field(ge=0, le=2)


def create_dashboard_app(store: Store, token: str, port: int, extra_hosts: list[str] | None = None) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
    for h in (extra_hosts or []):
        allowed_hosts.add(f"{h}:{port}")

    @app.middleware("http")
    async def guard(request: Request, call_next):
        if request.headers.get("host") not in allowed_hosts:
            return JSONResponse({"detail": "bad_host"}, status_code=403)
        if request.url.path.startswith("/api/") and not secrets.compare_digest(request.headers.get("x-ui-token", ""), token):
            return JSONResponse({"detail": "bad_token"}, status_code=403)
        resp = await call_next(request)
        resp.headers["Content-Security-Policy"] = ("default-src 'self'; style-src 'self' 'unsafe-inline'; "
                                                   "script-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Cache-Control"] = "no-store"
        return resp

    def since(hours: int) -> datetime:
        return utcnow() - timedelta(hours=max(1, min(hours, 24 * 90)))

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return resources.files("bonelia").joinpath("server/static/dashboard.html").read_text(encoding="utf-8")

    @app.get("/api/overview")
    def overview() -> dict[str, Any]:
        now = utcnow()
        tenants = {t["id"]: {**t, "repair_level": int(t["max_auto_level"])} for t in store.tenants()}
        devices = []
        for d in store.devices():
            scopes = json.loads(d["scopes"]) if isinstance(d["scopes"], str) else d["scopes"]
            seen = datetime.fromisoformat(d["last_seen_at"]) if d.get("last_seen_at") else None
            kind = _kind(scopes)
            devices.append({
                "id": d["id"], "tenant_id": d["tenant_id"], "customer": tenants.get(d["tenant_id"], {}).get("name"),
                "label": d["label"], "kind": kind, "status": d["status"], "last_seen_at": d.get("last_seen_at"),
                "online": bool(kind == "agent" and d["status"] == "active" and seen and now - seen < timedelta(minutes=ONLINE_MINUTES)),
                "last_status": json.loads(d["last_status"]) if d.get("last_status") else None, "scopes": scopes})
        important = {}
        for r in store.findings(since(24)):
            ev = DiagnosticEvent.model_validate_json(r["payload"])
            if ev.triage.value == "important":
                important[r["tenant_id"]] = important.get(r["tenant_id"], 0) + 1
        out_tenants = []
        for tid, t in tenants.items():
            ag = [d for d in devices if d["tenant_id"] == tid and d["kind"] == "agent" and d["status"] == "active"]
            out_tenants.append({"id": tid, "name": t["name"], "environment": t["environment"], "repair_level": t["repair_level"],
                                "agents": len(ag), "online": sum(1 for d in ag if d["online"]),
                                "important_24h": important.get(tid, 0)})
        return {"version": __version__, "tenants": out_tenants, "devices": devices, "online_minutes": ONLINE_MINUTES}

    @app.get("/api/findings")
    def findings(hours: int = 24, tenant: str | None = None, all: bool = False) -> dict[str, Any]:  # noqa: A002
        names = {t["id"]: t["name"] for t in store.tenants()}
        rows = []
        for r in store.findings(since(hours), tenant):
            ev = DiagnosticEvent.model_validate_json(r["payload"])
            if ev.triage.value == "harmless" or (not all and ev.triage.value != "important"):
                continue
            diag = Diagnosis.model_validate_json(r["diagnosis"]) if r.get("diagnosis") else None
            rows.append({
                "at": r["received_at"][:19], "customer": names.get(r["tenant_id"]), "device": r["label"],
                "triage": ev.triage.value, "triage_reason": ev.triage_reason, "title": ev.title, "app": ev.app.name,
                "occurrences": ev.occurrences, "repair_tool": ev.repair_tool,
                "evidence": [{"source": e.source, "code": e.code, "text": e.text[:300]} for e in ev.evidence[:1]],
                "diagnosis": None if diag is None else {
                    "produced_by": diag.produced_by, "summary": diag.summary,
                    "hypotheses": [{"cause": h.cause, "confidence": h.confidence.value} for h in diag.hypotheses],
                    "recommendations": [x.description for x in diag.recommendations], "warnings": diag.warnings}})
        return {"findings": rows}

    @app.get("/api/repairs")
    def repairs(hours: int = 168) -> dict[str, Any]:
        names = {t["id"]: t["name"] for t in store.tenants()}
        start = since(hours).isoformat()
        labels = {d["id"]: d["label"] for d in store.devices()}
        out = []
        for a in store.audit_log(None, 1000):
            if a["action"] not in ("tool.executed", "tool.denied") or a["at"] < start:
                continue
            d = json.loads(a["detail"])
            out.append({"at": a["at"][:19], "customer": names.get(a["tenant_id"]), "device": labels.get(a["device_id"]),
                        "action": a["action"], "tool_id": d.get("tool_id"), "params": d.get("params"),
                        "outcome": d.get("outcome") or ("denied" if a["action"] == "tool.denied" else None),
                        "verified": d.get("verified"), "reasons": d.get("reasons"),
                        "detail": d.get("detail")})
        return {"repairs": out}

    @app.post("/api/tenants/{tenant_id}/repair-level")
    def set_level(tenant_id: str, body: LevelBody) -> dict[str, Any]:
        if store.tenant(tenant_id) is None:
            raise HTTPException(404, "unknown_tenant")
        store.update_tenant(tenant_id, max_auto_level=min(body.level, int(RiskLevel.ADMIN_APPROVED)),
                            auto_tools=list(SAFE_AUTO_TOOLS) if body.level >= 1 else [],
                            production_writes_allowed=1 if body.level >= 1 else 0)
        return {"ok": True, "level": body.level}

    @app.post("/api/devices/{device_id}/revoke")
    def revoke(device_id: str) -> dict[str, Any]:
        if not store.revoke_device(device_id, actor="admin:dashboard"):
            raise HTTPException(404, "unknown_device")
        return {"ok": True}

    @app.post("/api/quit")
    def quit_app() -> dict[str, Any]:
        threading.Timer(0.5, lambda: os._exit(0)).start()
        return {"ok": True}

    return app


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _stable_token(data_dir) -> str:
    """A token that survives restarts, so a phone URL stays valid. Stored 0600, server-only."""
    from pathlib import Path

    p = Path(data_dir) / "dashboard.token"
    if p.is_file():
        return p.read_text(encoding="utf-8").strip()
    token = secrets.token_urlsafe(24)
    p.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(token)
    except FileExistsError:
        return p.read_text(encoding="utf-8").strip()
    return token


def serve_dashboard(store: Store, port: int = 0, open_browser: bool = True, host: str = "127.0.0.1",
                    data_dir=None) -> int:
    import uvicorn

    if host != "127.0.0.1" and not is_safe_bind(host):
        print("Panel yalnızca 127.0.0.1 veya bir Tailscale (100.x) adresinde açılabilir (şifreli özel ağ). / "
              "Nur auf 127.0.0.1 oder einer Tailscale-Adresse.", flush=True)
        return 2
    port = port or _free_port()
    remote = host != "127.0.0.1"
    # A phone over Tailscale needs a token that does not change every launch.
    token = _stable_token(data_dir) if remote and data_dir else secrets.token_urlsafe(24)
    extra = [host] if remote else []
    local_url = f"http://127.0.0.1:{port}/#{token}" if not remote else None
    phone_url = f"http://{host}:{port}/#{token}" if remote else None
    print(f"BONELİA AI Kontrol Paneli: {phone_url or local_url}", flush=True)
    if remote:
        print(f"Telefon/uzak erişim (Tailscale): {phone_url}", flush=True)
    if open_browser and not remote:
        threading.Timer(1.0, lambda: webbrowser.open(local_url)).start()
    uvicorn.run(create_dashboard_app(store, token, port, extra_hosts=extra), host=host, port=port, log_level="warning")
    return 0
