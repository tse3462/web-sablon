"""Local recovery screen, opened from the USB on the troubled PC. Works offline (no server)."""

from __future__ import annotations

import os
import secrets
import socket
import threading
import webbrowser
from importlib import resources
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from .. import PRODUCT_NAME, __version__
from ..repair.windows_tools import is_admin
from . import windows_recovery as wr


class OpBody(BaseModel):
    params: dict[str, Any] = Field(default_factory=dict)


def create_recovery_app(token: str, port: int, lang: str = "tr") -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    allowed = {f"127.0.0.1:{port}", f"localhost:{port}"}
    running: dict[str, bool] = {}

    @app.middleware("http")
    async def guard(request: Request, call_next):
        if request.headers.get("host") not in allowed:
            return JSONResponse({"detail": "bad_host"}, status_code=403)
        if request.url.path.startswith("/api/") and not secrets.compare_digest(request.headers.get("x-ui-token", ""), token):
            return JSONResponse({"detail": "bad_token"}, status_code=403)
        resp = await call_next(request)
        resp.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'"
        resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return resources.files("bonelia").joinpath("recovery/static/recovery.html").read_text(encoding="utf-8")

    @app.get("/api/status")
    def status() -> dict[str, Any]:
        return {"product": PRODUCT_NAME, "version": __version__, "language": lang, "is_admin": is_admin(),
                "bootrec_guide": wr.BOOTREC_GUIDE.get(lang, wr.BOOTREC_GUIDE["en"])}

    @app.post("/api/op/{name}")
    async def run_op(name: str, body: OpBody) -> dict[str, Any]:
        op = wr.OPERATIONS.get(name)
        if op is None:
            raise HTTPException(404, "unknown_operation")
        if not op["readonly"] and not is_admin():
            raise HTTPException(403, "needs_admin")
        if running.get(name):
            raise HTTPException(409, "already_running")
        running[name] = True
        try:
            res = await run_in_threadpool(op["fn"], body.params)
        finally:
            running[name] = False
        return {"ok": res.ok, "output": res.output[-6000:], "data": res.data, "error": res.error}

    @app.post("/api/quit")
    def quit_app() -> dict[str, Any]:
        threading.Timer(0.5, lambda: os._exit(0)).start()
        return {"ok": True}

    return app


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def serve_recovery(lang: str = "tr", port: int = 0, open_browser: bool = True) -> int:
    import uvicorn

    port = port or _free_port()
    token = secrets.token_urlsafe(24)
    url = f"http://127.0.0.1:{port}/#{token}"
    print(f"{PRODUCT_NAME} Kurtarma: {url}", flush=True)
    if open_browser:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    uvicorn.run(create_recovery_app(token, port, lang), host="127.0.0.1", port=port, log_level="warning")
    return 0
