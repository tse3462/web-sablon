"""Signed HTTP client from the Portable Monitor / Agent to the BONELİA AI Server."""

from __future__ import annotations

import ipaddress
import json
import re
from typing import Any
from urllib.parse import urlparse

import httpx

from .. import __version__
from ..contracts import AnalyzeRequest, AnalyzeResponse, DiagnosticEvent, EnrollRequest, EnrollResponse, SystemSnapshot
from ..security.crypto import (
    H_NONCE, H_SERVER_SIG, DeviceCredentials, generate_keypair, load_public_key, public_key_b64, sign_request, verify_response,
)


class ServerUnavailable(RuntimeError):
    """Network-level failure: server down, timeout, DNS, TLS."""


class ServerTimeout(ServerUnavailable):
    """The server was reached but did not answer in time (e.g. slow local AI model)."""


# Local models on CPU-only home PCs can need several minutes for one analysis.
AI_TIMEOUT_S = 600.0


class ServerError(RuntimeError):
    def __init__(self, status: int, detail: str):
        super().__init__(f"{status}: {detail}")
        self.status = status
        self.detail = detail


class FakeServerError(RuntimeError):
    """Response signature did not match the pinned server key."""


_TAILSCALE = ipaddress.ip_network("100.64.0.0/10")


def check_server_url(url: str) -> str:
    """Plain HTTP is only accepted for loopback or a Tailscale (WireGuard-encrypted) address."""
    u = urlparse(url)
    if u.scheme not in ("https", "http") or not u.hostname:
        raise ValueError("server URL must be http(s)://host[:port]")
    if u.path not in ("", "/"):
        raise ValueError("server URL must not contain a path")
    if u.scheme == "http":
        host = u.hostname
        try:
            ip = ipaddress.ip_address(host)
            ok = ip.is_loopback or ip in _TAILSCALE
        except ValueError:
            ok = host == "localhost" or host.endswith(".ts.net")
        if not ok:
            raise ValueError("plain http is only allowed to localhost or a Tailscale address; use https")
    return url.rstrip("/")


class ServerClient:
    def __init__(self, creds: DeviceCredentials, transport: httpx.BaseTransport | None = None, ca_file: str | None = None,
                 timeout_s: float = 30.0):
        self.creds = creds
        self.base = check_server_url(creds.server_url)
        self._server_pub = load_public_key(creds.server_public_key_b64)
        self._http = httpx.Client(base_url=self.base, transport=transport, verify=ca_file or True,
                                  timeout=httpx.Timeout(timeout_s, connect=5.0))

    def _request(self, method: str, path: str, payload: Any = None, timeout_s: float | None = None) -> dict[str, Any]:
        r = self._send(method, path, payload, timeout_s)
        try:
            data = r.json() if r.content else {}
        except ValueError:
            data = {}
        if r.status_code >= 400:
            raise ServerError(r.status_code, str(data.get("detail", "error")) if isinstance(data, dict) else "error")
        return data

    def _send(self, method: str, path: str, payload: Any = None, timeout_s: float | None = None) -> httpx.Response:
        """Signed request; the response signature is verified before anything is returned."""
        body = b"" if payload is None else json.dumps(payload, default=str, ensure_ascii=False).encode("utf-8")
        headers = sign_request(self.creds.private_key, self.creds.device_id, method, path, body)
        headers["Content-Type"] = "application/json"
        try:
            kw = {"timeout": httpx.Timeout(timeout_s, connect=5.0)} if timeout_s else {}
            r = self._http.request(method, path, content=body, headers=headers, **kw)
        except httpx.TimeoutException as exc:
            if isinstance(exc, httpx.ConnectTimeout):
                raise ServerUnavailable(type(exc).__name__) from exc
            raise ServerTimeout(type(exc).__name__) from exc
        except httpx.HTTPError as exc:
            raise ServerUnavailable(type(exc).__name__) from exc
        try:
            verify_response(self._server_pub, r.status_code, headers[H_NONCE], r.content, r.headers.get(H_SERVER_SIG))
        except ValueError as exc:
            raise FakeServerError(str(exc)) from exc
        return r

    def agent_update_info(self) -> dict[str, Any]:
        return self._request("GET", "/v1/agent/update")

    def download_agent_update(self) -> bytes:
        r = self._send("GET", "/v1/agent/update/file", timeout_s=300)
        if r.status_code != 200:
            raise ServerError(r.status_code, "update_download_failed")
        return r.content

    def health(self) -> dict[str, Any]:
        return self._request("GET", "/v1/health")

    def analyze(self, events: list[DiagnosticEvent], system: SystemSnapshot | None, allow_cloud: bool, lang: str) -> AnalyzeResponse:
        req = AnalyzeRequest(events=events[:25], system=system, allow_cloud=allow_cloud, language=lang)
        return AnalyzeResponse.model_validate(self._request("POST", "/v1/analyze", req.model_dump(mode="json"), AI_TIMEOUT_S))

    def chat(self, question: str, lang: str) -> dict[str, Any]:
        return self._request("POST", "/v1/chat", {"question": question, "language": lang}, AI_TIMEOUT_S)

    def adapter_health(self, adapter_id: str, lang: str, allow_cloud: bool = False) -> dict[str, Any]:
        """Server-side health analysis through an optional application adapter."""
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,40}", adapter_id):
            raise ValueError("invalid adapter id")
        return self._request("POST", f"/v1/adapters/{adapter_id}/health", {"language": lang, "allow_cloud": allow_cloud}, AI_TIMEOUT_S)

    def events(self) -> list[dict[str, Any]]:
        return self._request("GET", "/v1/events").get("events", [])

    def tools(self) -> list[dict[str, Any]]:
        return self._request("GET", "/v1/tools").get("tools", [])

    def run_tool(self, tool_id: str, params: dict[str, Any], dry_run: bool = True, approval_id: str | None = None) -> dict[str, Any]:
        return self._request("POST", "/v1/tools/run", {"tool_id": tool_id, "parameters": params, "dry_run": dry_run,
                                                       "approval_id": approval_id})

    def authorize_tool(self, tool_id: str, params: dict[str, Any], technician_confirmed: bool = False) -> dict[str, Any]:
        return self._request("POST", "/v1/tools/authorize", {"tool_id": tool_id, "parameters": params, "dry_run": False,
                                                             "technician_confirmed": technician_confirmed})

    def report_tool(self, grant_id: str, tool_id: str, params: dict[str, Any], outcome: str, verified: bool,
                    detail: dict[str, Any]) -> dict[str, Any]:
        return self._request("POST", "/v1/tools/report", {"grant_id": grant_id, "tool_id": tool_id, "parameters": params,
                                                          "outcome": outcome, "verified": verified, "detail": detail})

    def enroll_agent(self, label: str, server_url: str | None = None) -> DeviceCredentials:
        """Create credentials for a background agent on this PC, authorised by this USB / install key."""
        return self._child_device("/v1/agent/enroll", label, server_url)

    def create_install_key(self, label: str) -> DeviceCredentials:
        """Limited key (scope install:agent only) for passphrase-free installs from this USB."""
        return self._child_device("/v1/install-key", label, None)

    def _child_device(self, path: str, label: str, server_url: str | None) -> DeviceCredentials:
        import os

        key = generate_keypair()
        res = EnrollResponse.model_validate(self._request("POST", path,
                                                          {"device_label": label, "public_key_b64": public_key_b64(key)}))
        if res.server_public_key_b64 != self.creds.server_public_key_b64:
            raise FakeServerError("server key changed")
        return DeviceCredentials(server_url=check_server_url(server_url) if server_url else self.creds.server_url,
                                 device_id=res.device_id, tenant_id=res.tenant_id,
                                 scopes=res.scopes, server_public_key_b64=res.server_public_key_b64, private_key=key,
                                 data_key=os.urandom(32))

    def heartbeat(self, status: dict[str, Any]) -> dict[str, Any]:
        return self._request("POST", "/v1/heartbeat", {"status": status})

    def disk_progress(self, request: str, pct: int) -> dict[str, Any]:
        return self._request("POST", "/v1/disk-progress", {"request": request, "pct": pct})

    def disk_report(self, report: dict[str, Any]) -> dict[str, Any]:
        return self._request("POST", "/v1/disk-report", {"report": report})

    def adapters(self) -> list[dict[str, Any]]:
        return self._request("GET", "/v1/adapters").get("adapters", [])


def enroll(server_url: str, code: str, label: str, expected_server_key_b64: str | None = None,
           transport: httpx.BaseTransport | None = None, ca_file: str | None = None) -> DeviceCredentials:
    base = check_server_url(server_url)
    key = generate_keypair()
    req = EnrollRequest(enrollment_code=code, device_label=label, public_key_b64=public_key_b64(key), client_version=__version__)
    try:
        with httpx.Client(base_url=base, transport=transport, verify=ca_file or True, timeout=20.0) as http:
            r = http.post("/v1/enroll", json=req.model_dump())
    except httpx.HTTPError as exc:
        raise ServerUnavailable(type(exc).__name__) from exc
    if r.status_code != 200:
        raise ServerError(r.status_code, "enrollment_rejected")
    res = EnrollResponse.model_validate(r.json())
    if expected_server_key_b64 and res.server_public_key_b64 != expected_server_key_b64:
        raise FakeServerError("server key does not match the expected fingerprint")
    # The enrollment response itself must be signed by the key it announces.
    verify_response(load_public_key(res.server_public_key_b64), r.status_code, "", r.content, r.headers.get(H_SERVER_SIG))
    import os

    return DeviceCredentials(server_url=base, device_id=res.device_id, tenant_id=res.tenant_id, scopes=res.scopes,
                             server_public_key_b64=res.server_public_key_b64, private_key=key, data_key=os.urandom(32))
