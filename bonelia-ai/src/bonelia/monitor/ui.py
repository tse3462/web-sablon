"""Local graphical interface for the Portable Monitor.

Served on 127.0.0.1 only, on a random free port, protected by a random per-launch
token and a strict Host-header check (prevents other local pages / DNS rebinding
from driving the monitor). Opens in the default browser — no installation needed.
"""

from __future__ import annotations

import os
import secrets
import socket
import threading
import webbrowser
from importlib import resources
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from .. import PRODUCT_NAME, __version__
from .client import ServerError, ServerUnavailable
from .portable import watch_removal
from .reports import render_html
from .session import Session


class ScanBody(BaseModel):
    mode: str = Field(default="quick", pattern="^(quick|full|recent|app)$")
    app: str | None = Field(default=None, max_length=120)
    analyze: bool = False
    allow_cloud: bool = False


class UnlockBody(BaseModel):
    passphrase: str = Field(min_length=1, max_length=256)


class ChatBody(BaseModel):
    question: str = Field(min_length=1, max_length=2000)


class LangBody(BaseModel):
    language: str = Field(pattern="^(tr|de|en)$")


class ExportBody(BaseModel):
    dest: str = Field(min_length=1, max_length=500)


def create_ui_app(session: Session, token: str, port: int, transport=None) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
    lock = threading.Lock()

    @app.middleware("http")
    async def guard(request: Request, call_next):
        if request.headers.get("host") not in allowed_hosts:
            return JSONResponse({"detail": "bad_host"}, status_code=403)
        if request.url.path.startswith("/api/") and not secrets.compare_digest(request.headers.get("x-ui-token", ""), token):
            return JSONResponse({"detail": "bad_token"}, status_code=403)
        resp = await call_next(request)
        resp.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return resources.files("bonelia").joinpath("monitor/static/index.html").read_text(encoding="utf-8")

    @app.get("/api/status")
    def status() -> dict[str, Any]:
        scan = session.last_scan
        return {
            "product": PRODUCT_NAME, "version": __version__, "language": session.lang, "enrolled": session.enrolled,
            "unlocked": session.creds is not None, "device_id": session.creds.device_id if session.creds else None,
            "tenant_id": session.creds.tenant_id if session.creds else None,
            "server": session.server_status() if session.creds else {"connected": False},
            "system": scan.system.model_dump(mode="json") if scan and scan.system else None,
            "apps_detected": len(scan.apps) if scan else 0,
            "active_errors": sum(1 for e in scan.events if e.severity.value in ("error", "critical")) if scan else 0,
            "monitoring": "session_only",
        }

    @app.post("/api/unlock")
    def unlock(body: UnlockBody) -> dict[str, Any]:
        try:
            session.unlock(body.passphrase, transport=transport)
        except ValueError as exc:
            raise HTTPException(401, "wrong_passphrase") from exc
        except FileNotFoundError as exc:
            raise HTTPException(404, "not_enrolled") from exc
        return {"ok": True}

    @app.post("/api/language")
    def language(body: LangBody) -> dict[str, Any]:
        session.lang = body.language
        s = session.home.settings()
        s["language"] = body.language
        session.home.save_settings(s)
        return {"ok": True}

    @app.post("/api/scan")
    def scan(body: ScanBody) -> dict[str, Any]:
        with lock:
            session.scan(mode=body.mode, app_query=body.app or None)
            rep = session.analyze(allow_cloud=body.allow_cloud) if body.analyze else session.last_report
        apps = [a.model_dump(mode="json") for a in session.last_scan.apps[:200]] if session.last_scan else []
        return {"report": rep, "apps": apps}

    @app.get("/api/adapters")
    def adapters() -> dict[str, Any]:
        """Optional server-side adapters assigned to this customer (empty when none exist)."""
        if not session.client:
            return {"adapters": []}
        try:
            rows = session.client.adapters()
        except (ServerUnavailable, ServerError):
            return {"adapters": []}
        return {"adapters": [{"adapter_id": a["adapter_id"], "name": a.get("name", a["adapter_id"])} for a in rows
                             if a.get("load_status") == "available" and a.get("assigned_to_tenant")]}

    @app.post("/api/adapters/{adapter_id}/health")
    def adapter_health(adapter_id: str, allow_cloud: bool = False) -> dict[str, Any]:
        if not session.client:
            raise HTTPException(409, "not_unlocked")
        try:
            return session.client.adapter_health(adapter_id, session.lang, allow_cloud=allow_cloud)
        except ValueError as exc:
            raise HTTPException(404, "adapter_not_found") from exc
        except ServerUnavailable as exc:
            raise HTTPException(503, "server_unavailable") from exc
        except ServerError as exc:
            raise HTTPException(exc.status, exc.detail) from exc

    @app.post("/api/chat")
    def chat(body: ChatBody) -> dict[str, Any]:
        if not session.client:
            raise HTTPException(409, "not_unlocked")
        try:
            return session.client.chat(body.question, session.lang)
        except ServerUnavailable as exc:
            raise HTTPException(503, "server_unavailable") from exc
        except ServerError as exc:
            raise HTTPException(exc.status, exc.detail) from exc

    @app.get("/api/tools")
    def tools() -> dict[str, Any]:
        if not session.client:
            return {"tools": []}
        try:
            return {"tools": session.client.tools()}
        except (ServerUnavailable, ServerError):
            return {"tools": []}

    @app.post("/api/tools/{tool_id}/dry-run")
    def dry_run(tool_id: str) -> dict[str, Any]:
        if not session.client:
            raise HTTPException(409, "not_unlocked")
        try:
            res = session.client.run_tool(tool_id, {}, dry_run=True)
        except ServerError as exc:
            raise HTTPException(exc.status, exc.detail) from exc
        session.interventions.append({"tool_id": tool_id, "outcome": res.get("outcome"), "dry_run": True})
        return res

    @app.get("/api/report.html", response_class=HTMLResponse)
    def report_html() -> str:
        if not session.last_report:
            raise HTTPException(404, "no_report")
        return render_html(session.last_report)

    @app.post("/api/export")
    def export(body: ExportBody) -> dict[str, Any]:
        dest = Path(body.dest).expanduser().resolve()
        if dest == session.home.root or session.home.root in dest.parents:
            raise HTTPException(400, "export_must_be_outside_usb")
        try:
            files = session.export_last(dest)
        except RuntimeError as exc:
            raise HTTPException(404, "no_report") from exc
        return {"files": [str(f) for f in files]}

    return app


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def serve_ui(session: Session, port: int = 0, open_browser: bool = True) -> int:
    import uvicorn

    port = port or _free_port()
    token = secrets.token_urlsafe(24)
    app = create_ui_app(session, token, port)
    url = f"http://127.0.0.1:{port}/#{token}"
    print(f"{PRODUCT_NAME} {__version__} — {url}", flush=True)
    watch_removal(session.home.root, lambda: os._exit(0))  # USB removed => portable session ends
    if open_browser:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")
    return 0
