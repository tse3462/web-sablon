"""Server side of the password vault (user request 06.11.2026).

The server only keeps what it cannot read: the vault's public key, its private key wrapped under the
owner's master password, and sealed entries. Labels (title, customer, RustDesk ID) are plain so the list
can be shown before unlocking. Agents seal new RustDesk passwords to the public key; see security/vault.py.
"""

from __future__ import annotations

import json
import secrets
from typing import Any

from ..contracts import utcnow
from ..security.vault import fingerprint, valid_box, valid_meta

META_KEY = "vault_meta"
SCHEMA = """
create table if not exists vault_entries (
  id text primary key, kind text not null, device_id text, title text not null default '', customer text not null default '',
  rustdesk_id text, box text not null, rotate_done text, created_at text not null, updated_at text not null);
create unique index if not exists vault_entries_device on vault_entries(device_id) where kind = 'rustdesk';
create table if not exists vault_rotate (device_id text primary key, nonce text not null, at text not null);
"""


class VaultStore:
    def __init__(self, store):
        self.store = store
        with store._lock:
            store._db.executescript(SCHEMA)

    # ------------------------------------------------------------------ vault
    def meta(self) -> dict[str, Any] | None:
        m = self.store.get_setting(META_KEY)
        return m if valid_meta(m) else None

    def setup(self, meta: dict[str, Any]) -> str:
        """'ok', 'exists' (never overwritten: that would lock the owner out of every entry) or 'invalid'."""
        if not valid_meta(meta):
            return "invalid"
        with self.store._lock:
            if self.meta() is not None:
                return "exists"
            self.store.set_setting(META_KEY, meta)
        self.store.audit("admin:dashboard", "vault.created", {"fingerprint": fingerprint(meta["pub"])})
        return "ok"

    def reset(self) -> None:
        with self.store._lock:
            self.store._x("delete from vault_entries")
            self.store._x("delete from vault_rotate")
            self.store.delete_setting(META_KEY)
        self.store.audit("admin:dashboard", "vault.reset", {})

    # ------------------------------------------------------------------ entries
    def entries(self) -> list[dict[str, Any]]:
        devices = {d["id"]: d for d in self.store.devices()}
        tenants = {t["id"]: t["name"] for t in self.store.tenants()}
        rotate = {r["device_id"]: r["nonce"] for r in self.store._q("select device_id, nonce from vault_rotate")}
        out = []
        for r in self.store._q("select * from vault_entries order by customer, title"):
            e = {k: r[k] for k in ("id", "kind", "device_id", "title", "customer", "rustdesk_id", "updated_at")}
            e["box"] = json.loads(r["box"])
            dev = devices.get(r["device_id"]) if r["device_id"] else None
            if dev is not None:  # PC entries follow the device's current name and customer
                e["title"], e["customer"] = dev.get("label") or e["title"], tenants.get(dev.get("tenant_id"), e["customer"])
            e["rotating"] = bool(r["device_id"] and rotate.get(r["device_id"]) and rotate[r["device_id"]] != r["rotate_done"])
            out.append(e)
        return out

    def problems(self) -> list[dict[str, Any]]:
        """PCs whose agent could not give RustDesk a new password (reason as reported, e.g. "not_admin")."""
        tenants = {t["id"]: t["name"] for t in self.store.tenants()}
        out = []
        for d in self.store.devices():
            try:
                remote = (json.loads(d.get("last_status") or "{}") or {}).get("remote") or {}
            except (ValueError, AttributeError):
                continue
            if remote.get("vault_error"):
                out.append({"device_id": d["id"], "title": d.get("label") or "", "customer": tenants.get(d.get("tenant_id"), ""),
                            "rustdesk_id": remote.get("rustdesk_id"), "error": remote["vault_error"]})
        return out

    def save_manual(self, entry_id: str | None, title: str, customer: str, box: dict[str, Any]) -> str | None:
        """Owner's own entries (router, Wi-Fi, POS login …), sealed on the phone. None when the id is unknown."""
        now = utcnow().isoformat()
        if entry_id:
            rows = self.store._q("select id from vault_entries where id=? and kind='manual'", (entry_id,))
            if not rows:
                return None
            self.store._x("update vault_entries set title=?, customer=?, box=?, updated_at=? where id=?",
                          (title, customer, json.dumps(box), now, entry_id))
            return entry_id
        new_id = secrets.token_hex(8)
        self.store._x("insert into vault_entries (id, kind, title, customer, box, created_at, updated_at) values (?,?,?,?,?,?,?)",
                      (new_id, "manual", title, customer, json.dumps(box), now, now))
        return new_id

    def delete(self, entry_id: str) -> bool:
        if not self.store._q("select id from vault_entries where id=?", (entry_id,)):
            return False
        self.store._x("delete from vault_entries where id=?", (entry_id,))
        return True

    # ------------------------------------------------------------------ agents
    def request_rotation(self, device_id: str) -> bool:
        if self.store.device(device_id) is None:
            return False
        self.store._x("insert into vault_rotate (device_id, nonce, at) values (?,?,?) on conflict(device_id) do update set "
                      "nonce=excluded.nonce, at=excluded.at", (device_id, secrets.token_hex(8), utcnow().isoformat()))
        self.store.audit("admin:dashboard", "vault.rotation_requested", {}, device_id=device_id)
        return True

    def for_agent(self, device_id: str) -> dict[str, Any] | None:
        """What the heartbeat reply tells an agent: the public key, and a pending "new password" request."""
        meta = self.meta()
        if meta is None:
            return None
        rows = self.store._q("select nonce from vault_rotate where device_id=?", (device_id,))
        return {"pub": meta["pub"], "rotate": rows[0]["nonce"] if rows else None}

    def accept_from_agent(self, device_id: str, rustdesk_id: str | None, sealed: Any) -> bool:
        """Store a password an agent just set, sealed to the current vault. Anything else is refused."""
        meta = self.meta()
        if meta is None or not rustdesk_id or not isinstance(sealed, dict):
            return False
        if sealed.get("for") != fingerprint(meta["pub"]) or not valid_box(sealed.get("box")):
            return False
        rotate = sealed.get("rotate") if isinstance(sealed.get("rotate"), str) and len(sealed["rotate"]) <= 32 else None
        dev = self.store.device(device_id) or {}
        now = utcnow().isoformat()
        self.store._x(
            "insert into vault_entries (id, kind, device_id, title, customer, rustdesk_id, box, rotate_done, created_at, updated_at) "
            "values (?,?,?,?,?,?,?,?,?,?) on conflict(device_id) where kind = 'rustdesk' do update set "
            "rustdesk_id=excluded.rustdesk_id, box=excluded.box, rotate_done=excluded.rotate_done, updated_at=excluded.updated_at",
            (secrets.token_hex(8), "rustdesk", device_id, dev.get("label") or "", "", rustdesk_id, json.dumps(sealed["box"]),
             rotate, now, now))
        self.store.audit("device", "vault.rustdesk_password_set", {"rustdesk_id": rustdesk_id}, device_id=device_id)
        return True
