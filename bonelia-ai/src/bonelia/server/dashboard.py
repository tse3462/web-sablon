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
from urllib.parse import urlsplit
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from pydantic import BaseModel, Field

from .. import __version__
from ..contracts import Diagnosis, DiagnosticEvent, RiskLevel, utcnow
from ..repair.builtin_tools import SAFE_AUTO_TOOLS
from .notify import TELEGRAM_KEY, TelegramAPI, build_notifier, extract_token
from .repair import TOKEN_KEY as REPAIR_TOKEN_KEY, TOKEN_RE, valid_repo
from .uptime import UptimeMonitor, check_settings, normalize_keyword
from .vault_store import VaultStore
from .disk_store import SAFE_KEYS, DiskStore, tree_nodes
from . import rescue_report
from . import brain as brain_mod
from ..security.vault import valid_box
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
    # Uptime monitor: a separate check address (e.g. https://…/health) and a text the answer must contain
    # (e.g. "database":"ok", so the program's database is checked too). Monitoring is on by default.
    check_url: str | None = Field(default=None, max_length=500)
    keyword: str | None = Field(default=None, max_length=200)
    monitor: bool = True
    # Intervention links, one per line: "Supabase https://…" (label, then the address)
    links: str | list[dict[str, str]] | None = Field(default=None)
    # AI repair: the program's GitHub repository ("owner/name") and, once, a key with "Actions: read and write"
    repair_repo: str | None = Field(default=None, max_length=201)
    repair_token: str | None = Field(default=None, max_length=300)
    # The program's admin page: a tap on its card in "Programlar" opens it (user request 06.11.2026)
    admin_url: str | None = Field(default=None, max_length=500)


APPS_KEY = "apps"
MAX_APPS = 40
_URL = re.compile(r"^https?://[^\s<>\"'`]+$", re.IGNORECASE)


_LINK = re.compile(r"(https?://[^\s<>\"'`]+)", re.IGNORECASE)


def parse_links(raw: str | list[dict[str, str]] | None) -> list[dict[str, str]]:
    """Intervention links for a program: "Supabase https://…" per line; lines without an http(s) address are dropped."""
    lines = raw[:2000].splitlines() if isinstance(raw, str) else [f"{x.get('label', '')} {x.get('url', '')}" for x in raw or [] if isinstance(x, dict)]
    out = []
    for line in lines[:20]:
        m = _LINK.search(line)
        if not m or len(m.group(1)) > 500:
            continue
        label = line[:m.start()].strip(" \t:-|–") or (urlsplit(m.group(1)).hostname or "Link")
        out.append({"label": label[:30], "url": m.group(1)})
    return out[:6]


class VaultSetup(BaseModel):
    meta: dict[str, Any]


class VaultEntry(BaseModel):
    id: str | None = Field(default=None, max_length=40)
    title: str = Field(min_length=1, max_length=60)
    customer: str = Field(default="", max_length=60)
    box: dict[str, Any]


class VaultReset(BaseModel):
    confirm: str = Field(max_length=10)


class DiskCleanBody(BaseModel):
    safe: list[str] = Field(default_factory=list, max_length=10)
    items: list[str] = Field(default_factory=list, max_length=400)
    folders: list[str] = Field(default_factory=list, max_length=20)
    moves: list[str] = Field(default_factory=list, max_length=20)
    drive: str | None = Field(default=None, max_length=40)


class RescueBody(BaseModel):
    hung: bool = True
    memory: bool = True


class CloseProgramBody(BaseModel):
    pid: int = Field(ge=1, lt=2**32)
    name: str = Field(max_length=80)
    restart: bool = False


class BrainBody(BaseModel):
    enabled: bool | None = None
    key: str | None = Field(default=None, max_length=300)
    monthly_limit: float | None = None
    model: str | None = Field(default=None, max_length=40)


class BrainCustomer(BaseModel):
    tenant_id: str = Field(max_length=80)
    allowed: bool


class SetupValue(BaseModel):
    value: str = Field(max_length=300)


class PilotSettings(BaseModel):
    app_id: str | None = Field(default=None, max_length=40)
    on: bool | None = None
    ai_cap: int | None = Field(default=None, ge=0, le=500)


class SetupLink(BaseModel):
    app_id: str = Field(max_length=40)
    repo: str = Field(max_length=201)


class SetupDbUrl(BaseModel):
    pooler: str = Field(max_length=400)
    password: str = Field(max_length=80)


class DevelopBody(BaseModel):
    target: str = Field(max_length=60)
    request: str = Field(max_length=2000)


class TokenBody(BaseModel):
    token: str = Field(max_length=4000)  # may be the whole @BotFather message; the token is extracted


# absolute Windows paths only: "D:\Kasa\Yedek" or a network share "\\NAS\yedek"
_WIN_PATH = re.compile(r"^(?:[A-Za-z]:\\|\\\\[^\\/:*?\"<>|]+\\[^\\/:*?\"<>|]+)[^:*?\"<>|]{0,250}$")


def create_dashboard_app(store: Store, token: str, port: int, extra_hosts: list[str] | None = None,
                         telegram_api: TelegramAPI | None = None, http_transport: Any = None) -> FastAPI:
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

    @app.get("/vault.js")
    def vault_js() -> Response:
        # The vault's cryptography (bundled @noble libraries, see web/vault/entry.js): runs only on the phone.
        return Response(resources.files("bonelia").joinpath("server/static/vault.js").read_text(encoding="utf-8"),
                        media_type="application/javascript; charset=utf-8")

    # ---------------------------------------------------------------- password vault
    vaults = VaultStore(store)

    @app.get("/api/vault")
    def vault_get() -> dict[str, Any]:
        meta = vaults.meta()
        return {"meta": meta, "entries": vaults.entries() if meta else [], "problems": vaults.problems() if meta else []}

    @app.post("/api/vault/setup")
    def vault_setup(body: VaultSetup) -> dict[str, Any]:
        outcome = vaults.setup(body.meta)
        if outcome != "ok":
            raise HTTPException(409 if outcome == "exists" else 422, "vault_" + outcome)
        return {"meta": vaults.meta(), "entries": []}

    @app.post("/api/vault/entries")
    def vault_save(body: VaultEntry) -> dict[str, Any]:
        if vaults.meta() is None:
            raise HTTPException(409, "vault_missing")
        if not valid_box(body.box) or not body.title.strip():
            raise HTTPException(422, "invalid_entry")
        if vaults.save_manual(body.id, body.title.strip(), body.customer.strip(), body.box) is None:
            raise HTTPException(404, "unknown_entry")
        return {"meta": vaults.meta(), "entries": vaults.entries()}

    @app.post("/api/vault/entries/{entry_id}/delete")
    def vault_delete(entry_id: str) -> dict[str, Any]:
        if not vaults.delete(entry_id):
            raise HTTPException(404, "unknown_entry")
        return {"meta": vaults.meta(), "entries": vaults.entries()}

    @app.post("/api/vault/rotate/{device_id}")
    def vault_rotate(device_id: str) -> dict[str, Any]:
        """"New password": the PC's agent sets a fresh RustDesk password within a few minutes."""
        if not vaults.request_rotation(device_id):
            raise HTTPException(404, "unknown_device")
        return {"meta": vaults.meta(), "entries": vaults.entries()}

    @app.post("/api/vault/reset")
    def vault_reset(body: VaultReset) -> dict[str, Any]:
        if body.confirm != "SIL":
            raise HTTPException(422, "confirm_needed")
        vaults.reset()
        return {"meta": None, "entries": []}

    # ---------------------------------------------------------------- disk space (06.11.2026)
    disks = DiskStore(store)

    def _merge_policy(device_id: str, **changes: Any) -> dict[str, Any]:
        pol = store.device_policy(device_id)
        pol.update(changes)
        store.set_device_policy(device_id, pol, actor="admin:dashboard")
        return pol

    def _disk_view(device_id: str) -> dict[str, Any]:
        dev = store.device(device_id)
        if dev is None:
            raise HTTPException(404, "unknown_device")
        rep, pol = disks.latest(device_id), store.device_policy(device_id)
        tenant = store.tenant(dev["tenant_id"]) or {}
        pending = pol.get("disk_cleanup")
        scan_pending = bool(pol.get("disk_scan")) and pol.get("disk_scan") != (rep or {}).get("scan_request")
        prog = disks.progress(device_id)
        return {"device": {"id": device_id, "label": dev["label"], "customer": tenant.get("name", "")},
                "report": rep, "history": disks.history(device_id),
                "pending": {"safe": pending.get("safe", []), "files": len(pending.get("files", [])), "folders": len(pending.get("folders", [])),
                            "moves": len(pending.get("moves", [])), "bytes": pending.get("bytes", 0),
                            "progress": prog["pct"] if prog and prog["request"] == pending.get("id") else None} if pending else None,
                "scan_pending": scan_pending,
                "progress": {"pct": prog["pct"], "at": prog["at"]} if scan_pending and prog and prog["request"] == pol.get("disk_scan") else None,
                "consent": int(tenant.get("max_auto_level") or 0) >= 1}

    # ---------- the brain (07.11.2026): Claude for important problems, with a monthly limit and customer consent
    def brain_view() -> dict[str, Any]:
        s = brain_mod.settings(store)
        key = store.get_setting(brain_mod.KEY_SETTING)
        return {**s, "key_set": isinstance(key, str) and bool(brain_mod.KEY_RE.match(key)),
                "spent_month": round(store.ai_spend_all("month"), 4),
                "customers": [{"id": x["id"], "name": x["name"], "allowed": bool(x["cloud_ai_allowed"])} for x in store.tenants()]}

    @app.get("/api/brain")
    def brain_get() -> dict[str, Any]:
        return brain_view()

    @app.post("/api/brain")
    def brain_set(body: BrainBody) -> dict[str, Any]:
        s = brain_mod.settings(store)
        if body.key is not None and body.key.strip():
            k = body.key.strip()
            if not brain_mod.KEY_RE.match(k):
                raise HTTPException(422, "invalid_key")
            store.set_setting(brain_mod.KEY_SETTING, k)  # this PC only; never sent back to the panel
        if body.monthly_limit is not None:
            if not 0 < body.monthly_limit <= brain_mod.MAX_LIMIT:
                raise HTTPException(422, "invalid_limit")
            s["monthly_limit"] = round(float(body.monthly_limit), 2)
        if body.model is not None:
            if body.model not in brain_mod.MODELS:
                raise HTTPException(422, "invalid_model")
            s["model"] = body.model
        if body.enabled is not None:
            s["enabled"] = body.enabled
        store.set_setting(brain_mod.SETTINGS_KEY, s)
        store.audit("admin:dashboard", "settings.brain", {**s, "key_changed": bool(body.key)})
        return brain_view()

    @app.post("/api/brain/customer")
    def brain_customer(body: BrainCustomer) -> dict[str, Any]:
        if store.tenant(body.tenant_id) is None:
            raise HTTPException(404, "unknown_tenant")
        store.update_tenant(body.tenant_id, cloud_ai_allowed=1 if body.allowed else 0)
        return brain_view()

    @app.post("/api/brain/test")
    def brain_test() -> dict[str, Any]:
        """One tiny question to Claude: is the key right? Counts against the monthly limit like every call."""
        key = store.get_setting(brain_mod.KEY_SETTING)
        if not isinstance(key, str) or not brain_mod.KEY_RE.match(key):
            raise HTTPException(409, "no_key")
        s = brain_mod.settings(store)
        if store.ai_spend_all("month") >= s["monthly_limit"]:
            raise HTTPException(409, "limit_reached")
        from ..ai.claude import claude_prices
        from ..ai.costs import PriceTable
        from ..ai.providers import ProviderError
        from ..ai.router import AICallRecord

        p = brain_mod.make_provider(key, s["model"])
        try:
            res = p.complete("Answer with JSON only.", 'Reply {"ok": true}', 50)
            ok = '"ok"' in res.text
        except ProviderError as exc:
            return {**brain_view(), "ok": False, "error": str(exc)[:120]}
        cost = PriceTable(claude_prices()).estimate(p.name, p.model, res.input_tokens, res.output_tokens, True)
        store.record_ai_call(AICallRecord(tenant_id="system", provider=p.name, model=p.model, input_tokens=res.input_tokens,
                                          output_tokens=res.output_tokens, estimated_cost=cost, latency_ms=res.latency_ms,
                                          category="brain_test", ok=ok))
        return {**brain_view(), "ok": ok}

    # ---------- "Geliştir" (07.11.2026): a wish -> Claude on its own branch with tests -> the owner approves
    def develop_view(d) -> dict[str, Any]:
        return {"targets": [{k: t[k] for k in ("id", "name", "base", "live")} for t in d.targets()],
                "ready": d.github.ready(), "requests": d.requests()}

    # ---------- setup guide of the own programs' maintenance (07.11.2026)
    def setup_guide(app_id: str):
        from .setup_guide import SetupGuide
        g = SetupGuide(store)
        app_ = g.app(app_id)
        if app_ is None:
            raise HTTPException(404, "unknown_app")
        return g, app_

    def setup_overview() -> dict[str, Any]:
        from .setup_guide import suggest_repo
        linked, unlinked = [], []
        for a in apps_list():
            if not isinstance(a, dict):
                continue
            if a.get("repair_repo") and valid_repo(str(a["repair_repo"])):
                linked.append({"id": a["id"], "name": a.get("name"), "repo": a["repair_repo"]})
            else:
                unlinked.append({"id": a["id"], "name": a.get("name"), "suggest": suggest_repo(a)})
        return {"linked": linked, "unlinked": unlinked}

    @app.get("/api/setup")
    def setup_get() -> dict[str, Any]:
        return setup_overview()

    @app.post("/api/setup/link")
    def setup_link(body: SetupLink) -> dict[str, Any]:
        """Step 0 of the guide: the program's GitHub repository, without leaving the guide."""
        repo = body.repo.strip()
        if not valid_repo(repo):
            raise HTTPException(422, "invalid_repo")
        apps = apps_list()
        hit = next((a for a in apps if isinstance(a, dict) and a.get("id") == body.app_id), None)
        if hit is None:
            raise HTTPException(404, "unknown_app")
        hit["repair_repo"] = repo
        store.set_setting(APPS_KEY, apps)
        store.audit("admin:dashboard", "setup.repo_linked", {"id": body.app_id, "repair_repo": repo})
        return setup_overview()

    @app.get("/api/setup/{app_id}")
    def setup_status(app_id: str) -> dict[str, Any]:
        g, app_ = setup_guide(app_id)
        return g.status(app_)

    @app.post("/api/setup/{app_id}/supabase")
    def setup_supabase(app_id: str, body: SetupValue) -> dict[str, Any]:
        from .setup_guide import supabase_ref
        g, app_ = setup_guide(app_id)
        ref = supabase_ref(body.value)
        if ref is None:
            raise HTTPException(422, "invalid_supabase")
        apps = apps_list()
        for a in apps:
            if a.get("id") == app_id:
                a["supabase_ref"] = ref
        store.set_setting(APPS_KEY, apps)
        return g.status(g.app(app_id))

    @app.post("/api/setup/{app_id}/anthropic")
    def setup_anthropic(app_id: str) -> dict[str, Any]:
        from . import brain as brain_mod
        g, app_ = setup_guide(app_id)
        key = store.get_setting(brain_mod.KEY_SETTING)
        if not isinstance(key, str) or not brain_mod.KEY_RE.match(key):
            raise HTTPException(409, "no_key")
        r = g.put_secret(app_["repair_repo"], "ANTHROPIC_API_KEY", key)
        if r != "saved":
            raise HTTPException(409, "secrets_" + r)
        store.audit("admin:dashboard", "setup.secret_saved", {"repo": app_["repair_repo"], "name": "ANTHROPIC_API_KEY"})
        return g.status(app_)

    @app.post("/api/setup/{app_id}/dburl")
    def setup_dburl(app_id: str, body: SetupDbUrl) -> dict[str, Any]:
        from .setup_guide import health_url
        g, app_ = setup_guide(app_id)
        ref = app_.get("supabase_ref")
        if not ref:
            raise HTTPException(409, "no_supabase")
        try:
            url = health_url(body.pooler, body.password, ref)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        r = g.put_secret(app_["repair_repo"], "DB_HEALTH_URL", url)
        if r != "saved":
            raise HTTPException(409, "secrets_" + r)
        store.audit("admin:dashboard", "setup.secret_saved", {"repo": app_["repair_repo"], "name": "DB_HEALTH_URL"})
        # The same read-only monitor address stays on this PC for the free five-minute check (autopilot, 07.11.2026):
        # that role sees statistics only, never a customer's data, and can change nothing.
        from .autopilot import DB_URLS_KEY
        urls = store.get_setting(DB_URLS_KEY) or {}
        store.set_setting(DB_URLS_KEY, {**urls, app_id: url})
        return g.status(app_)

    # ---------- weekly database check of the own programs (07.11.2026)
    @app.get("/api/dbhealth")
    def dbhealth_get() -> dict[str, Any]:
        from .db_health import DbHealthWatch
        w = DbHealthWatch(store)
        return {"programs": [{"id": a["id"], "name": a.get("name") or a["repair_repo"]} for a in w.programs()], "reports": w.reports()}

    @app.post("/api/dbhealth/{app_id}/run")
    def dbhealth_run(app_id: str) -> dict[str, Any]:
        from .db_health import DbHealthWatch
        r = DbHealthWatch(store).run_now(app_id)
        if r == "unknown_app":
            raise HTTPException(404, r)
        if r != "started":
            raise HTTPException(409, r)
        return {"result": r}

    @app.get("/api/develop")
    def develop_get() -> dict[str, Any]:
        from .develop import DevelopDesk
        return develop_view(DevelopDesk(store))

    @app.post("/api/develop")
    def develop_submit(body: DevelopBody) -> dict[str, Any]:
        from .develop import DevelopDesk
        d = DevelopDesk(store)
        r = d.submit(body.target, body.request)
        if isinstance(r, str):
            raise HTTPException({"invalid_request": 422, "unknown_target": 404}.get(r, 409), r)
        return develop_view(d)

    @app.post("/api/develop/{rid}/approve")
    def develop_approve(rid: str) -> dict[str, Any]:
        from .develop import DevelopDesk
        d = DevelopDesk(store)
        r = d.approve(rid)
        if r != "merged":
            raise HTTPException(404 if r == "unknown" else 409, r)
        return develop_view(d)

    @app.get("/api/backup")
    def backup_get() -> dict[str, Any]:
        """When the server was last backed up (written by BONELIA-Yedekle.bat, also its weekly automatic run)."""
        rec = store.get_setting("server_backup")
        return {"last": rec if isinstance(rec, dict) else None}

    # ---------- automatic rescue (06.11.2026): two switches, and "close" for a program the PC reported
    @app.get("/api/rescue")
    def rescue_get() -> dict[str, bool]:
        return rescue_report.settings(store)

    @app.post("/api/rescue")
    def rescue_set(body: RescueBody) -> dict[str, bool]:
        store.set_setting(rescue_report.SETTINGS_KEY, {"hung": body.hung, "memory": body.memory})
        store.audit("admin:dashboard", "settings.rescue", {"hung": body.hung, "memory": body.memory})
        return rescue_report.settings(store)

    @app.post("/api/devices/{device_id}/close-program")
    def close_program(device_id: str, body: CloseProgramBody) -> dict[str, Any]:
        dev = store.device(device_id)
        if dev is None:
            raise HTTPException(404, "unknown_device")
        st = json.loads(dev["last_status"]) if dev.get("last_status") else {}
        top = ((st.get("rescue") or {}).get("top") or []) if isinstance(st, dict) else []
        if not any(x.get("pid") == body.pid and x.get("name") == body.name for x in top if isinstance(x, dict)):
            raise HTTPException(409, "not_reported")  # only what the PC itself listed; it checks again before closing
        req = {"id": secrets.token_hex(8), "pid": body.pid, "name": body.name, "restart": body.restart}
        _merge_policy(device_id, close_request=req)
        return {"requested": req}

    @app.get("/api/disk/{device_id}")
    def disk_get(device_id: str) -> dict[str, Any]:
        return _disk_view(device_id)

    @app.post("/api/disk/{device_id}/scan")
    def disk_scan(device_id: str) -> dict[str, Any]:
        if store.device(device_id) is None:
            raise HTTPException(404, "unknown_device")
        _merge_policy(device_id, disk_scan=secrets.token_hex(6))
        return _disk_view(device_id)

    @app.post("/api/disk/{device_id}/clean")
    def disk_clean(device_id: str, body: DiskCleanBody) -> dict[str, Any]:
        """Only what the owner picked from the PC's own report; the agent re-checks every file before deleting."""
        view = _disk_view(device_id)
        rep = view["report"]
        if rep is None:
            raise HTTPException(409, "no_report")
        if not view["consent"]:
            raise HTTPException(409, "consent_needed")
        offered = {c["key"] for c in rep["categories"] if c["kind"] == "safe"} & SAFE_KEYS
        by_id = {s["id"]: s for s in rep["suggestions"]}
        deletable = {n["id"]: n for n in tree_nodes(rep) if n.get("id") and n.get("deletable")}
        drives = [d["name"] for d in rep.get("backup_drives") or []]
        if (not (body.safe or body.items or body.folders or body.moves) or not set(body.safe) <= offered or not set(body.items) <= set(by_id)
                or not set(body.folders) <= set(deletable) or not set(body.moves) <= set(deletable)
                or (body.moves and body.drive not in drives)):
            raise HTTPException(422, "invalid_selection")
        moves = [{"path": deletable[i]["path"], "bytes": deletable[i]["bytes"], "drive": body.drive} for i in dict.fromkeys(body.moves)]
        files = [{k: by_id[i][k] for k in ("path", "bytes", "mtime")} for i in dict.fromkeys(body.items)]
        folders = [{"path": deletable[i]["path"], "bytes": deletable[i]["bytes"]} for i in dict.fromkeys(body.folders)]
        total = (sum(f["bytes"] for f in files) + sum(f["bytes"] for f in folders) + sum(m["bytes"] for m in moves)
                 + sum(c["bytes"] for c in rep["categories"] if c["key"] in body.safe))
        _merge_policy(device_id, disk_cleanup={"id": secrets.token_hex(8), "safe": list(dict.fromkeys(body.safe)), "files": files,
                                               "folders": folders, "moves": moves, "bytes": total})
        dev = store.device(device_id)
        store.audit("admin:dashboard", "disk.cleanup_requested", {"safe": body.safe, "files": len(files),
                                                                  "folders": [f["path"] for f in folders],
                                                                  "moves": [m["path"] + " -> " + m["drive"] for m in moves], "bytes": total},
                    tenant_id=dev["tenant_id"], device_id=device_id)
        return _disk_view(device_id)

    @app.get("/api/overview")
    def overview() -> dict[str, Any]:
        now = utcnow()
        tenants = {t["id"]: {**t, "repair_level": int(t["max_auto_level"])} for t in store.tenants()}
        devices = []
        disk_sums = disks.summaries()
        for d in store.devices():
            scopes = json.loads(d["scopes"]) if isinstance(d["scopes"], str) else d["scopes"]
            seen = datetime.fromisoformat(d["last_seen_at"]) if d.get("last_seen_at") else None
            kind = _kind(scopes)
            devices.append({
                "id": d["id"], "tenant_id": d["tenant_id"], "customer": tenants.get(d["tenant_id"], {}).get("name"),
                "label": d["label"], "kind": kind, "status": d["status"], "last_seen_at": d.get("last_seen_at"),
                "online": bool(kind == "agent" and d["status"] == "active" and seen and now - seen < timedelta(minutes=ONLINE_MINUTES)),
                "last_status": json.loads(d["last_status"]) if d.get("last_status") else None, "scopes": scopes,
                "backup": (json.loads(d["policy"]) if d.get("policy") else {}).get("backup"),
                "disk": disk_sums.get(d["id"])})
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
        check_url = (body.check_url or "").strip() or None
        if check_url and not _URL.match(check_url):
            raise HTTPException(422, "invalid_url")
        admin_url = (body.admin_url or "").strip() or None
        if admin_url and not _URL.match(admin_url):
            raise HTTPException(422, "invalid_url")
        repair_repo = (body.repair_repo or "").strip() or None
        if repair_repo and not valid_repo(repair_repo):
            raise HTTPException(422, "invalid_repo")
        repair_token = (body.repair_token or "").strip()
        if repair_token and not TOKEN_RE.match(repair_token):
            raise HTTPException(422, "invalid_repair_token")
        item = {"id": body.id or secrets.token_hex(6), "name": name, "url": url, "icon": (body.icon.strip() or "🔗")[:8],
                "check_url": check_url, "keyword": normalize_keyword(body.keyword), "monitor": body.monitor,
                "links": parse_links(body.links), "repair_repo": repair_repo, "admin_url": admin_url}
        apps = apps_list()
        idx = next((i for i, a in enumerate(apps) if a.get("id") == item["id"]), None)
        if idx is None:
            if body.id:
                raise HTTPException(404, "unknown_app")
            if len(apps) >= MAX_APPS:
                raise HTTPException(409, "too_many_apps")
            apps.append(item)
        else:
            changed = check_settings(apps[idx]) != check_settings(item)
            apps[idx] = item
            if changed:  # the old minutes measured another address or text: start fresh
                uptime.reset(item["id"])
        store.set_setting(APPS_KEY, apps)
        if repair_token:  # kept on this PC only, never shown again; empty field = keep the stored key
            store.set_setting(REPAIR_TOKEN_KEY, repair_token)
        store.audit("admin:dashboard", "settings.app_saved", {"name": name, "url": url, "repair_repo": repair_repo})
        return {"apps": apps}

    # ---------------------------------------------------------------- uptime of the own programs
    uptime = UptimeMonitor(store, build_notifier(store, {}), transport=http_transport)

    @app.get("/api/uptime")
    def uptime_get() -> dict[str, Any]:
        return {"apps": uptime.summary(), "repair_ready": uptime.repair.ready()}

    @app.post("/api/uptime/{app_id}/repair")
    def uptime_repair(app_id: str) -> dict[str, Any]:
        """"Let the AI look" button: starts the program's GitHub job; the result comes by Telegram."""
        outcome = uptime.start_repair_by_hand(app_id)
        if outcome != "started":
            code = {"unknown_app": 404, "too_soon": 429, "refused": 502}.get(outcome, 409)
            raise HTTPException(code, "repair_" + outcome)
        store.audit("admin:dashboard", "uptime.repair_started", {"app_id": app_id})
        return {"started": True, "apps": uptime.summary()}

    # ---------- autopilot of the own programs (07.11.2026)
    def pilot_view() -> dict[str, Any]:
        from .uptime import STATE_KEY as UPTIME_STATE
        return uptime.pilot.summary(store.get_setting(UPTIME_STATE) or {})

    @app.get("/api/pilot")
    def pilot_get() -> dict[str, Any]:
        return pilot_view()

    @app.post("/api/pilot/settings")
    def pilot_settings(body: PilotSettings) -> dict[str, Any]:
        from .autopilot import SETTINGS_KEY as PILOT_KEY
        s = uptime.pilot.settings()
        if body.app_id is not None and body.on is not None:
            if not any(a.get("id") == body.app_id for a in apps_list()):
                raise HTTPException(404, "unknown_app")
            off = [x for x in s["off"] if x != body.app_id] + ([] if body.on else [body.app_id])
            s["off"] = off
        if body.ai_cap is not None:
            s["ai_cap"] = body.ai_cap
        store.set_setting(PILOT_KEY, s)
        store.audit("admin:dashboard", "autopilot.settings", {"off": s["off"], "ai_cap": s["ai_cap"]})
        return pilot_view()

    @app.post("/api/pilot/{app_id}/approve")
    def pilot_approve(app_id: str) -> dict[str, Any]:
        """The owner's "Onayla" for a fix the autopilot did not take live by itself."""
        from .uptime import STATE_KEY as UPTIME_STATE
        app_ = next((a for a in apps_list() if a.get("id") == app_id and a.get("repair_repo")), None)
        if app_ is None:
            raise HTTPException(404, "unknown_app")
        with uptime._lock:
            states = store.get_setting(UPTIME_STATE) or {}
            st = states.setdefault(app_id, {"fails": 0, "alerted": False})
            result = uptime.pilot.approve(app_, st)
            if result != "merged":
                raise HTTPException(409, "pilot_" + result)
            store.set_setting(UPTIME_STATE, states)
        store.audit("admin:dashboard", "autopilot.approved", {"app_id": app_id, "branch": st["pilot"].get("branch")})
        return {"result": result, **pilot_view()}

    @app.post("/api/uptime/check")
    def uptime_check_now() -> dict[str, Any]:
        uptime.run_once()  # same checks the server runs every minute; messages are de-duplicated
        return {"apps": uptime.summary()}

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
