"""BONELİA AI Control Center (v0.1): local web panel on the home server.

Served on 127.0.0.1 only, random port, random per-launch token and strict Host
check (same protection as the USB UI). It reads the server database directly; it
is not reachable from the network.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import secrets
import socket
import threading
import webbrowser
from pathlib import Path
from datetime import datetime, timedelta
from importlib import resources
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from pydantic import BaseModel, Field

from .. import __version__
from ..contracts import Diagnosis, DiagnosticEvent, RiskLevel, utcnow
from ..repair.builtin_tools import SAFE_AUTO_TOOLS
from .notify import TELEGRAM_KEY, TelegramAPI, extract_token
from .store import Store

ONLINE_MINUTES = 15  # agents report every 5 minutes
_TAILSCALE = ipaddress.ip_network("100.64.0.0/10")


def tailscale_ipv4() -> str | None:
    """This PC's Tailscale IPv4 (100.64/10), so the panel can bind itself for phone access."""
    import ipaddress
    import shutil
    import subprocess

    exe = shutil.which("tailscale") or r"C:\Program Files\Tailscale\tailscale.exe"
    try:
        out = subprocess.run([exe, "ip", "-4"], capture_output=True, text=True, timeout=10,
                             creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)).stdout
    except (OSError, subprocess.TimeoutExpired):
        return None
    for line in out.splitlines():
        line = line.strip()
        try:
            if ipaddress.ip_address(line) in _TAILSCALE:
                return line
        except ValueError:
            continue
    return None


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


class BackupBody(BaseModel):
    paths: list[str] = Field(default_factory=list, max_length=5)
    max_age_days: int = Field(default=2, ge=1, le=60)


class AppBody(BaseModel):
    id: str | None = Field(default=None, max_length=40)
    name: str = Field(min_length=1, max_length=40)
    url: str = Field(min_length=8, max_length=500)
    icon: str = Field(default="🔗", max_length=8)


APPS_KEY = "apps"
MAX_APPS = 40
_URL = re.compile(r"^https?://[^\s<>\"'`]+$", re.IGNORECASE)


class TokenBody(BaseModel):
    token: str = Field(max_length=4000)  # may be the whole @BotFather message; the token is extracted


# absolute Windows paths only: "D:\Kasa\Yedek" or a network share "\\NAS\yedek"
_WIN_PATH = re.compile(r"^(?:[A-Za-z]:\\|\\\\[^\\/:*?\"<>|]+\\[^\\/:*?\"<>|]+)[^:*?\"<>|]{0,250}$")


def create_dashboard_app(store: Store, token: str, port: int, extra_hosts: list[str] | None = None,
                         telegram_api: TelegramAPI | None = None) -> FastAPI:
    tg = telegram_api or TelegramAPI()
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

    # Tab and phone home-screen icon (BNL digital mark); no token needed, the host check above still applies.
    _icons = {"/favicon.ico": "image/x-icon", "/apple-touch-icon.png": "image/png", "/icon.svg": "image/svg+xml"}

    def _icon_route(path: str, media: str):
        async def icon() -> Response:
            data = resources.files("bonelia").joinpath("server/static/" + path.lstrip("/")).read_bytes()
            return Response(data, media_type=media, headers={"cache-control": "public, max-age=86400"})
        app.get(path)(icon)

    for _path, _media in _icons.items():
        _icon_route(_path, _media)

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
                "last_status": json.loads(d["last_status"]) if d.get("last_status") else None, "scopes": scopes,
                "backup": (json.loads(d["policy"]) if d.get("policy") else {}).get("backup")})
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

    @app.post("/api/devices/{device_id}/delete")
    def delete_device(device_id: str) -> dict[str, Any]:
        if not store.delete_device(device_id, actor="admin:dashboard"):
            raise HTTPException(404, "unknown_device")
        return {"ok": True}

    @app.post("/api/devices/{device_id}/backup-policy")
    def set_backup_policy(device_id: str, body: BackupBody) -> dict[str, Any]:
        """Backup folders this PC's agent checks (newest file age). Empty list = no folder check."""
        if store.device(device_id) is None:
            raise HTTPException(404, "unknown_device")
        paths = []
        for raw in body.paths:
            p = raw.strip().strip('"')
            if not p:
                continue
            if not _WIN_PATH.match(p) or any(ord(c) < 32 for c in p):
                raise HTTPException(422, "invalid_path")
            paths.append(p)
        policy = store.device_policy(device_id)
        if paths:
            policy["backup"] = {"paths": paths[:5], "max_age_days": body.max_age_days}
        else:
            policy.pop("backup", None)
        store.set_device_policy(device_id, policy, actor="admin:dashboard")
        return {"ok": True, "backup": policy.get("backup")}

    # ---------------------------------------------------------------- "My apps" launcher
    # Links to the owner's own programs (admin panels, web apps). Only the address is kept --
    # never a password: each program does its own login (the phone's password manager fills it).
    def apps_list() -> list[dict[str, Any]]:
        apps = store.get_setting(APPS_KEY)
        return apps if isinstance(apps, list) else []

    @app.get("/api/apps")
    def apps_get() -> dict[str, Any]:
        return {"apps": apps_list()}

    @app.post("/api/apps")
    def apps_save(body: AppBody) -> dict[str, Any]:
        url, name = body.url.strip(), body.name.strip()
        if not _URL.match(url):
            raise HTTPException(422, "invalid_url")
        if not name:
            raise HTTPException(422, "invalid_name")
        item = {"id": body.id or secrets.token_hex(6), "name": name, "url": url, "icon": (body.icon.strip() or "🔗")[:8]}
        apps = apps_list()
        idx = next((i for i, a in enumerate(apps) if a.get("id") == item["id"]), None)
        if idx is None:
            if body.id:
                raise HTTPException(404, "unknown_app")
            if len(apps) >= MAX_APPS:
                raise HTTPException(409, "too_many_apps")
            apps.append(item)
        else:
            apps[idx] = item
        store.set_setting(APPS_KEY, apps)
        store.audit("admin:dashboard", "settings.app_saved", {"name": name, "url": url})
        return {"apps": apps}

    @app.post("/api/apps/{app_id}/delete")
    def apps_delete(app_id: str) -> dict[str, Any]:
        apps = apps_list()
        keep = [a for a in apps if a.get("id") != app_id]
        if len(keep) == len(apps):
            raise HTTPException(404, "unknown_app")
        store.set_setting(APPS_KEY, keep)
        store.audit("admin:dashboard", "settings.app_deleted", {"id": app_id})
        return {"apps": keep}

    @app.post("/api/apps/{app_id}/move")
    def apps_move(app_id: str, step: int = -1) -> dict[str, Any]:
        apps = apps_list()
        i = next((i for i, a in enumerate(apps) if a.get("id") == app_id), None)
        if i is None:
            raise HTTPException(404, "unknown_app")
        j = max(0, min(len(apps) - 1, i + (1 if step > 0 else -1)))
        apps[i], apps[j] = apps[j], apps[i]
        store.set_setting(APPS_KEY, apps)
        return {"apps": apps}

    # ---------------------------------------------------------------- Telegram (phone notifications)
    def tg_state() -> dict[str, Any]:
        c = store.get_setting(TELEGRAM_KEY) or {}
        state = "on" if c.get("token") and c.get("chat_id") else ("pending" if c.get("token") else "off")
        return {"state": state, "bot": c.get("bot"), "chat_name": c.get("chat_name")}  # never the token

    @app.get("/api/settings/telegram")
    def telegram_get() -> dict[str, Any]:
        return tg_state()

    @app.post("/api/settings/telegram/token")
    def telegram_token(body: TokenBody) -> dict[str, Any]:
        tok = extract_token(body.token)
        if not tok:
            raise HTTPException(422, "invalid_token")
        bot = tg.bot_name(tok)
        if not bot:
            raise HTTPException(400, "token_rejected")
        store.set_setting(TELEGRAM_KEY, {"token": tok, "bot": bot, "chat_id": None})
        store.audit("admin:dashboard", "settings.telegram_token", {"bot": bot})
        return tg_state()

    @app.post("/api/settings/telegram/connect")
    def telegram_connect() -> dict[str, Any]:
        c = store.get_setting(TELEGRAM_KEY) or {}
        if not c.get("token"):
            raise HTTPException(409, "no_token")
        found = tg.latest_chat(c["token"])
        if not found:
            raise HTTPException(409, "no_message")
        c["chat_id"], c["chat_name"] = found
        if not tg.send(c["token"], c["chat_id"], "✅ BONELİA AI: bildirimler artık bu sohbete gelecek. / "
                                                 "Benachrichtigungen kommen ab jetzt in diesen Chat."):
            raise HTTPException(502, "send_failed")
        store.set_setting(TELEGRAM_KEY, c)
        store.audit("admin:dashboard", "settings.telegram_on", {"bot": c.get("bot")})
        return tg_state()

    @app.post("/api/settings/telegram/test")
    def telegram_test() -> dict[str, Any]:
        c = store.get_setting(TELEGRAM_KEY) or {}
        if not (c.get("token") and c.get("chat_id")):
            raise HTTPException(409, "not_connected")
        if not tg.send(c["token"], c["chat_id"], "🔔 BONELİA AI test bildirimi / Testbenachrichtigung"):
            raise HTTPException(502, "send_failed")
        return {"ok": True}

    @app.post("/api/settings/telegram/off")
    def telegram_off() -> dict[str, Any]:
        store.delete_setting(TELEGRAM_KEY)
        store.audit("admin:dashboard", "settings.telegram_off", {})
        return tg_state()

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

    if host == "auto":  # find the Tailscale address ourselves; fall back to local if Tailscale is off
        detected = tailscale_ipv4()
        if detected:
            host = detected
        else:
            print("Tailscale adresi bulunamadı; panel yalnızca bu bilgisayarda açılıyor. / "
                  "Keine Tailscale-Adresse; Panel nur lokal.", flush=True)
            host = "127.0.0.1"
    if host != "127.0.0.1" and not is_safe_bind(host):
        print("Panel yalnızca 127.0.0.1 veya bir Tailscale (100.x) adresinde açılabilir (şifreli özel ağ). / "
              "Nur auf 127.0.0.1 oder einer Tailscale-Adresse.", flush=True)
        return 2
    port = port or _free_port()
    remote = host != "127.0.0.1"
    # A phone over Tailscale needs a token that does not change every launch.
    token = _stable_token(data_dir) if remote and data_dir else secrets.token_urlsafe(24)
    extra = [host] if remote else []
    # The token is passed as a query parameter (not a #fragment): iOS "Add to Home Screen"
    # preserves the query in the saved shortcut, so the home-screen icon keeps working.
    local_url = f"http://127.0.0.1:{port}/?t={token}" if not remote else None
    phone_url = f"http://{host}:{port}/?t={token}" if remote else None
    print(f"BONELİA AI Kontrol Paneli: {phone_url or local_url}", flush=True)
    if remote:
        print(f"Telefon/uzak erişim (Tailscale): {phone_url}", flush=True)
        if data_dir:
            try:
                (Path(data_dir) / "panel-url.txt").write_text(
                    "BONELİA AI Kontrol Paneli — telefon/uzak erişim adresi\n"
                    "Tailscale bağlıyken telefon tarayıcısına bu TAM adresi girin.\n"
                    "Safari'de açıldıktan sonra Paylaş > 'Ana Ekrana Ekle' yapabilirsiniz;\n"
                    "kısayol anahtarı da hatırlar, bir daha adres girmenize gerek kalmaz.\n\n"
                    + phone_url + "\n", encoding="utf-8")
            except OSError:
                pass
    if open_browser and not remote:
        threading.Timer(1.0, lambda: webbrowser.open(local_url)).start()
    uvicorn.run(create_dashboard_app(store, token, port, extra_hosts=extra), host=host, port=port, log_level="warning")
    return 0
