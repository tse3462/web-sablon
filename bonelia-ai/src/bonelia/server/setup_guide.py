"""Setup guide of the own programs' maintenance (user request 07.11.2026).

The panel walks the owner through what only he can do (a permission on his GitHub key, one SQL in Supabase,
copying one address) and does the rest itself: it checks each step against GitHub, and it writes the repository
secrets ANTHROPIC_API_KEY (the brain's key) and DB_HEALTH_URL (built from the Supabase pooler address and the
password the panel generated) with GitHub's own encryption. The password never leaves the owner's browser except
inside that request, and BONELIA does not keep it.
"""

from __future__ import annotations

import base64
import re
from typing import Any
from urllib.parse import quote

import httpx

from .repair import API, GitHubRepair, valid_repo

WORKFLOWS = ("auto-repair.yml", "claude-gelistir.yml", "db-saglik.yml")
SECRETS = ("ANTHROPIC_API_KEY", "DB_HEALTH_URL")
MONITOR_ROLE = "bonelia_health_monitor"
REF_RE = re.compile(r"^[a-z]{20}$")
POOLER_RE = re.compile(r"^postgres(?:ql)?://postgres\.([a-z]{20})(?::[^@\s]*)?@([a-z0-9.-]+\.pooler\.supabase\.com):(5432|6543)/postgres(?:\?\S*)?$")
PASSWORD_RE = re.compile(r"^[A-Za-z0-9]{24,64}$")
TRANSPORT: httpx.BaseTransport | None = None  # tests replace the network


def supabase_ref(text: str) -> str | None:
    """A project id from what the owner pastes: the id itself, https://<id>.supabase.co or a dashboard address."""
    t = (text or "").strip().lower()
    m = re.search(r"(?:^|//|/project/)([a-z]{20})(?:\.supabase\.co|[/?#]|$)", t)
    return m.group(1) if m else None


def health_url(pooler: str, password: str, ref: str) -> str:
    """DB_HEALTH_URL for the monitor role, from the "Session pooler" address Supabase shows (any password in it is dropped)."""
    m = POOLER_RE.match((pooler or "").strip())
    if not m:
        raise ValueError("invalid_pooler")
    if m.group(1) != ref:
        raise ValueError("other_project")
    if not PASSWORD_RE.match(password or ""):
        raise ValueError("invalid_password")
    # Session mode (5432): the check sets session parameters. Supabase's pooler certificate is not in public stores.
    return f"postgresql://{MONITOR_ROLE}.{ref}:{quote(password, safe='')}@{m.group(2)}:5432/postgres?sslmode=no-verify"


class SetupGuide:
    def __init__(self, store, github: GitHubRepair | None = None):
        self.store = store
        self.github = github or GitHubRepair(store, TRANSPORT)

    def app(self, app_id: str) -> dict[str, Any] | None:
        return next((a for a in self.store.get_setting("apps") or [] if isinstance(a, dict) and a.get("id") == app_id
                     and a.get("repair_repo") and valid_repo(str(a["repair_repo"]))), None)

    def status(self, app: dict[str, Any]) -> dict[str, Any]:
        from . import brain as brain_mod

        repo = app["repair_repo"]
        key = self.store.get_setting(brain_mod.KEY_SETTING)
        out: dict[str, Any] = {"repo": repo, "supabase_ref": app.get("supabase_ref"), "token": self.github.ready(),
                               "actions": "unknown", "workflows": {w: False for w in WORKFLOWS}, "secrets_access": "unknown",
                               "secrets": {s: False for s in SECRETS},
                               "brain_key": isinstance(key, str) and bool(brain_mod.KEY_RE.match(key))}
        if not out["token"]:
            return out
        try:
            with self.github._client() as c:
                r = c.get(f"{API}/repos/{repo}/actions/workflows", params={"per_page": 100})
                out["actions"] = "ok" if r.status_code == 200 else "denied"
                if r.status_code == 200:
                    have = {str(w.get("path", "")).rsplit("/", 1)[-1] for w in r.json().get("workflows", [])}
                    out["workflows"] = {w: w in have for w in WORKFLOWS}
                s = c.get(f"{API}/repos/{repo}/actions/secrets", params={"per_page": 100})
                out["secrets_access"] = "ok" if s.status_code == 200 else "denied"
                if s.status_code == 200:
                    names = {x.get("name") for x in s.json().get("secrets", [])}
                    out["secrets"] = {n: n in names for n in SECRETS}
        except httpx.HTTPError:
            out["actions"] = "unreachable"
        return out

    def put_secret(self, repo: str, name: str, value: str) -> str:
        """Write one repository secret with GitHub's public key (libsodium sealed box)."""
        from nacl.public import PublicKey, SealedBox

        if name not in SECRETS or not value:
            return "invalid"
        try:
            with self.github._client() as c:
                k = c.get(f"{API}/repos/{repo}/actions/secrets/public-key")
                if k.status_code != 200:
                    return "denied"
                pk = k.json()
                sealed = SealedBox(PublicKey(base64.b64decode(pk["key"]))).encrypt(value.encode("utf-8"))
                r = c.put(f"{API}/repos/{repo}/actions/secrets/{name}",
                          json={"encrypted_value": base64.b64encode(sealed).decode("ascii"), "key_id": pk["key_id"]})
            return "saved" if r.status_code in (201, 204) else "denied"
        except (httpx.HTTPError, KeyError, ValueError):
            return "unreachable"
