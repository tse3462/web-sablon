"""Server persistence (SQLite for v0.1; schema kept portable to PostgreSQL).

Tenant isolation rule: every read of tenant data takes `tenant_id` as a required
argument that the API layer derives from the AUTHENTICATED device — never from a
request body.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import sqlite3
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from ..ai.router import AICallRecord
from ..contracts import Diagnosis, DiagnosticEvent, RiskLevel, new_id, utcnow
from ..repair.policy import Approval
from ..security.crypto import hash_secret

SCHEMA = """
create table if not exists tenants (
  id text primary key, name text not null, cloud_ai_allowed integer not null default 0,
  max_auto_level integer not null default 0, auto_tools text not null default '[]',
  daily_budget real not null default 0, monthly_budget real not null default 0,
  retention_days integer not null default 90, environment text not null default 'test',
  production_writes_allowed integer not null default 0, created_at text not null);
create table if not exists devices (
  id text primary key, tenant_id text not null references tenants(id), label text not null,
  public_key text not null unique, scopes text not null, status text not null default 'active',
  created_at text not null, last_seen_at text, revoked_at text);
create table if not exists enrollment_codes (
  code_hash text primary key, tenant_id text not null references tenants(id), scopes text not null,
  expires_at text not null, used_at text, created_at text not null);
create table if not exists events (
  id text primary key, tenant_id text not null, device_id text not null, fingerprint text not null,
  app_id text not null, category text not null, severity text not null, title text not null,
  occurred_at text not null, received_at text not null, payload text not null);
create index if not exists events_tenant_idx on events (tenant_id, received_at desc);
create table if not exists diagnoses (
  id integer primary key autoincrement, tenant_id text not null, event_id text not null,
  produced_by text not null, payload text not null, created_at text not null);
create table if not exists diagnosis_cache (
  tenant_id text not null, fingerprint text not null, payload text not null, created_at text not null,
  primary key (tenant_id, fingerprint));
create table if not exists ai_calls (
  id integer primary key autoincrement, tenant_id text not null, provider text not null, model text not null,
  input_tokens integer not null, output_tokens integer not null, estimated_cost real, latency_ms integer not null,
  category text not null, ok integer not null, created_at text not null);
create table if not exists approvals (
  id text primary key, tenant_id text not null, tool_id text not null, params_hash text not null,
  approved_by text not null, expires_at text not null, used_at text, created_at text not null);
create table if not exists tool_runs (
  id integer primary key autoincrement, tenant_id text not null, tool_id text not null, at text not null);
create table if not exists nonces (device_id text not null, nonce text not null, at text not null,
  primary key (device_id, nonce));
create table if not exists audit (
  id integer primary key autoincrement, at text not null, tenant_id text, device_id text, actor text not null,
  action text not null, detail text not null, prev_hash text not null, hash text not null);
create table if not exists settings (
  key text primary key, value text not null, updated_at text not null);
create table if not exists notifications (
  key text primary key, last_at text not null, count integer not null default 1);
create table if not exists knowledge (
  id integer primary key autoincrement, app_name text not null, app_version text, error_code text not null,
  symptoms text not null, verified_cause text not null, solution_steps text not null, required_permissions text,
  risk_level integer not null default 0, valid_versions text, test_result text not null,
  approved_by text not null, created_at text not null);
"""


def new_enrollment_code() -> str:
    """160-bit one-time code, base32 in groups of 4: letters/digits only, easy to type, never starts with '-'."""
    raw = base64.b32encode(secrets.token_bytes(20)).decode("ascii")
    return "-".join(raw[i:i + 4] for i in range(0, len(raw), 4))


def normalize_code(code: str) -> str:
    """Case-insensitive; ignores spaces and dashes the technician may type differently."""
    return "".join(ch for ch in (code or "").upper() if ch.isalnum())


def _iso(dt: datetime) -> str:
    return dt.isoformat()


class Store:
    def __init__(self, path: Path | str):
        self.path = str(path)
        self._lock = threading.RLock()
        self._db = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        self._db.execute("pragma journal_mode=wal")
        self._db.execute("pragma foreign_keys=on")
        self._db.executescript(SCHEMA)
        self._migrate()

    def _migrate(self) -> None:
        cols = {r["name"] for r in self._q("pragma table_info(devices)")}
        if "last_status" not in cols:  # added after v0.1 first release
            self._x("alter table devices add column last_status text")
        if "policy" not in cols:  # per-device settings pushed to the agent (e.g. backup folders)
            self._x("alter table devices add column policy text")

    def _q(self, sql: str, args: tuple = ()) -> list[sqlite3.Row]:
        with self._lock:
            return list(self._db.execute(sql, args))

    def _x(self, sql: str, args: tuple = ()) -> int:
        with self._lock:
            cur = self._db.execute(sql, args)
            return cur.rowcount

    # ------------------------------------------------------------------ tenants
    def create_tenant(self, name: str, cloud_ai_allowed: bool = False, daily_budget: float = 0.0,
                      monthly_budget: float = 0.0, environment: str = "test") -> str:
        tid = new_id("ten")
        self._x("insert into tenants (id, name, cloud_ai_allowed, daily_budget, monthly_budget, environment, created_at)"
                " values (?,?,?,?,?,?,?)", (tid, name[:120], int(cloud_ai_allowed), daily_budget, monthly_budget,
                                           environment, _iso(utcnow())))
        self.audit("admin", "tenant.create", {"name": name[:120], "environment": environment}, tenant_id=tid)
        return tid

    def tenant(self, tenant_id: str) -> dict[str, Any] | None:
        rows = self._q("select * from tenants where id=?", (tenant_id,))
        if not rows:
            return None
        d = dict(rows[0])
        d["auto_tools"] = json.loads(d["auto_tools"])
        return d

    def update_tenant(self, tenant_id: str, **fields: Any) -> None:
        allowed = {"cloud_ai_allowed", "max_auto_level", "auto_tools", "daily_budget", "monthly_budget",
                   "retention_days", "production_writes_allowed"}
        for k, v in fields.items():
            if k not in allowed:
                raise ValueError(f"field not updatable: {k}")
            if k == "max_auto_level" and int(v) >= int(RiskLevel.CRITICAL):
                raise ValueError("level 3 cannot be enabled in v0.1")
            if k == "auto_tools":
                v = json.dumps(sorted(set(v)))
            self._x(f"update tenants set {k}=? where id=?", (v, tenant_id))
        self.audit("admin", "tenant.update", {k: (v if k != "auto_tools" else list(v)) for k, v in fields.items()}, tenant_id=tenant_id)

    def tenants(self) -> list[dict[str, Any]]:
        return [dict(r) for r in self._q("select id, name, environment, cloud_ai_allowed, max_auto_level, created_at from tenants")]

    # ------------------------------------------------------------------ enrollment & devices
    def create_enrollment_code(self, tenant_id: str, scopes: list[str], ttl_minutes: int = 30) -> str:
        if self.tenant(tenant_id) is None:
            raise ValueError("unknown tenant")
        code = new_enrollment_code()
        self._x("insert into enrollment_codes (code_hash, tenant_id, scopes, expires_at, created_at) values (?,?,?,?,?)",
                (hash_secret(normalize_code(code)), tenant_id, json.dumps(sorted(set(scopes))), _iso(utcnow() + timedelta(minutes=ttl_minutes)),
                 _iso(utcnow())))
        self.audit("admin", "enrollment.code_created", {"scopes": sorted(set(scopes)), "ttl_min": ttl_minutes}, tenant_id=tenant_id)
        return code

    AGENT_SCOPES = ("agent", "repair:windows")  # report findings + repair ITS OWN PC; cannot read customer data
    INSTALL_KEY_SCOPES = ("install:agent",)  # can only enroll agents (lives unencrypted on the USB)

    def create_agent_device(self, tenant_id: str, label: str, public_key_b64: str, by_device: str,
                            scopes: tuple[str, ...] = AGENT_SCOPES, kind: str = "agent") -> dict[str, Any]:
        """An authorised USB enrolls a background agent (or an install key) for the SAME customer."""
        if self._q("select 1 from devices where public_key=?", (public_key_b64,)):
            raise PermissionError("key_reused")
        did = new_id("dev")
        scopes = sorted(scopes)
        self._x("insert into devices (id, tenant_id, label, public_key, scopes, created_at) values (?,?,?,?,?,?)",
                (did, tenant_id, label[:80], public_key_b64, json.dumps(scopes), _iso(utcnow())))
        self.audit("device", f"{kind}.enrolled_by_usb", {"label": label[:80], "by_device": by_device}, tenant_id=tenant_id,
                   device_id=did)
        return {"device_id": did, "tenant_id": tenant_id, "scopes": scopes}

    def redeem_enrollment(self, code: str, label: str, public_key_b64: str) -> dict[str, Any]:
        with self._lock:
            rows = self._q("select * from enrollment_codes where code_hash=?", (hash_secret(normalize_code(code)),))
            if not rows:
                raise PermissionError("invalid_code")
            row = rows[0]
            if row["used_at"] is not None:
                raise PermissionError("code_used")
            if datetime.fromisoformat(row["expires_at"]) <= utcnow():
                raise PermissionError("code_expired")
            if self._q("select 1 from devices where public_key=?", (public_key_b64,)):
                raise PermissionError("key_reused")
            did = new_id("dev")
            self._x("update enrollment_codes set used_at=? where code_hash=?", (_iso(utcnow()), row["code_hash"]))
            self._x("insert into devices (id, tenant_id, label, public_key, scopes, created_at) values (?,?,?,?,?,?)",
                    (did, row["tenant_id"], label[:80], public_key_b64, row["scopes"], _iso(utcnow())))
        self.audit("device", "device.enrolled", {"label": label[:80]}, tenant_id=row["tenant_id"], device_id=did)
        return {"device_id": did, "tenant_id": row["tenant_id"], "scopes": json.loads(row["scopes"])}

    def device(self, device_id: str) -> dict[str, Any] | None:
        rows = self._q("select * from devices where id=?", (device_id,))
        if not rows:
            return None
        d = dict(rows[0])
        d["scopes"] = json.loads(d["scopes"])
        return d

    def devices(self, tenant_id: str | None = None) -> list[dict[str, Any]]:
        if tenant_id:
            rows = self._q("select id, tenant_id, label, scopes, status, created_at, last_seen_at, revoked_at, last_status, policy "
                           "from devices where tenant_id=?", (tenant_id,))
        else:
            rows = self._q("select id, tenant_id, label, scopes, status, created_at, last_seen_at, revoked_at, last_status, policy from devices")
        return [dict(r) for r in rows]

    def touch_device(self, device_id: str) -> None:
        self._x("update devices set last_seen_at=? where id=?", (_iso(utcnow()), device_id))

    def notification_due(self, key: str, quiet: timedelta) -> bool:
        rows = self._q("select last_at from notifications where key=?", (key,))
        return not rows or datetime.fromisoformat(rows[0]["last_at"]) <= utcnow() - quiet

    def mark_notified(self, key: str) -> None:
        self._x("insert into notifications (key, last_at) values (?,?) on conflict(key) do update set "
                "last_at=excluded.last_at, count=count+1", (key[:300], _iso(utcnow())))

    def clear_notification(self, key: str) -> None:
        self._x("delete from notifications where key=?", (key,))

    def device_policy(self, device_id: str) -> dict[str, Any]:
        rows = self._q("select policy from devices where id=?", (device_id,))
        if not rows or not rows[0]["policy"]:
            return {}
        try:
            return json.loads(rows[0]["policy"])
        except ValueError:
            return {}

    def set_device_policy(self, device_id: str, policy: dict[str, Any], actor: str = "admin") -> bool:
        dev = self.device(device_id)
        if dev is None:
            return False
        self._x("update devices set policy=? where id=?", (json.dumps(policy, sort_keys=True) if policy else None, device_id))
        self.audit(actor, "device.policy_changed", {"policy": policy}, tenant_id=dev["tenant_id"], device_id=device_id)
        return True

    # ------------------------------------------------------------------ settings (server-wide, e.g. Telegram)
    def get_setting(self, key: str) -> Any:
        rows = self._q("select value from settings where key=?", (key,))
        if not rows:
            return None
        try:
            return json.loads(rows[0]["value"])
        except ValueError:
            return None

    def set_setting(self, key: str, value: Any) -> None:
        self._x("insert into settings (key, value, updated_at) values (?,?,?) on conflict(key) do update set "
                "value=excluded.value, updated_at=excluded.updated_at", (key, json.dumps(value), _iso(utcnow())))

    def delete_setting(self, key: str) -> None:
        self._x("delete from settings where key=?", (key,))

    def set_device_status(self, device_id: str, status: dict[str, Any]) -> None:
        self._x("update devices set last_status=? where id=?", (json.dumps(status, default=str)[:4000], device_id))

    def findings(self, since: datetime, tenant_id: str | None = None, limit: int = 300) -> list[dict[str, Any]]:
        """Events with device label and the latest diagnosis (AI or rules) for the control panel."""
        sql = ("select e.id, e.tenant_id, e.device_id, d.label, e.received_at, e.payload, "
               "(select g.payload from diagnoses g where g.event_id = e.id order by g.id desc limit 1) as diagnosis "
               "from events e left join devices d on d.id = e.device_id where e.received_at >= ?")
        args: tuple = (_iso(since),)
        if tenant_id:
            sql += " and e.tenant_id = ?"
            args += (tenant_id,)
        return [dict(r) for r in self._q(sql + " order by e.received_at desc limit ?", args + (limit,))]

    def update_device_scopes(self, device_id: str, add: list[str] = (), remove: list[str] = ()) -> list[str] | None:
        dev = self.device(device_id)
        if dev is None:
            return None
        scopes = sorted((set(dev["scopes"]) | set(add)) - set(remove))
        self._x("update devices set scopes=? where id=?", (json.dumps(scopes), device_id))
        self.audit("admin", "device.scopes_changed", {"add": list(add), "remove": list(remove)}, tenant_id=dev["tenant_id"],
                   device_id=device_id)
        return scopes

    def revoke_device(self, device_id: str, actor: str = "admin") -> bool:
        dev = self.device(device_id)
        if dev is None:
            return False
        self._x("update devices set status='revoked', revoked_at=? where id=?", (_iso(utcnow()), device_id))
        self.audit(actor, "device.revoked", {}, tenant_id=dev["tenant_id"], device_id=device_id)
        return True

    def delete_device(self, device_id: str, actor: str = "admin") -> bool:
        """Permanently remove a device from the list (e.g. an old test or revoked entry).
        The tamper-evident audit log keeps a record of the deletion."""
        dev = self.device(device_id)
        if dev is None:
            return False
        self._x("delete from devices where id=?", (device_id,))
        self._x("delete from nonces where device_id=?", (device_id,))
        self.audit(actor, "device.deleted", {"label": dev.get("label")}, tenant_id=dev["tenant_id"], device_id=device_id)
        return True

    def use_nonce(self, device_id: str, nonce: str) -> bool:
        """Return False if the nonce was already seen (replay)."""
        with self._lock:
            try:
                self._db.execute("insert into nonces (device_id, nonce, at) values (?,?,?)", (device_id, nonce, _iso(utcnow())))
            except sqlite3.IntegrityError:
                return False
            self._db.execute("delete from nonces where at < ?", (_iso(utcnow() - timedelta(minutes=15)),))
        return True

    # ------------------------------------------------------------------ events & diagnoses
    def save_event(self, tenant_id: str, device_id: str, ev: DiagnosticEvent) -> DiagnosticEvent:
        ev = ev.model_copy(update={"tenant_id": tenant_id, "device_id": device_id, "event_id": new_id("evt")})
        self._x("insert into events (id, tenant_id, device_id, fingerprint, app_id, category, severity, title, occurred_at,"
                " received_at, payload) values (?,?,?,?,?,?,?,?,?,?,?)",
                (ev.event_id, tenant_id, device_id, ev.fingerprint, ev.app.app_id, ev.category.value, ev.severity.value,
                 ev.title, _iso(ev.occurred_at), _iso(utcnow()), ev.model_dump_json()))
        return ev

    def events(self, tenant_id: str, limit: int = 100) -> list[DiagnosticEvent]:
        rows = self._q("select payload from events where tenant_id=? order by received_at desc limit ?", (tenant_id, limit))
        return [DiagnosticEvent.model_validate_json(r["payload"]) for r in rows]

    def recent_events(self, since: datetime, tenant_id: str | None = None) -> list[dict[str, Any]]:
        sql = ("select e.tenant_id, e.device_id, d.label, e.received_at, e.payload from events e "
               "left join devices d on d.id = e.device_id where e.received_at >= ?")
        args: tuple = (_iso(since),)
        if tenant_id:
            sql += " and e.tenant_id = ?"
            args += (tenant_id,)
        return [dict(r) for r in self._q(sql + " order by e.received_at desc limit 500", args)]

    def previous_occurrences(self, tenant_id: str, fingerprint: str) -> int:
        return self._q("select count(*) c from events where tenant_id=? and fingerprint=?", (tenant_id, fingerprint))[0]["c"]

    def save_diagnosis(self, tenant_id: str, d: Diagnosis) -> None:
        self._x("insert into diagnoses (tenant_id, event_id, produced_by, payload, created_at) values (?,?,?,?,?)",
                (tenant_id, d.event_id, d.produced_by, d.model_dump_json(), _iso(utcnow())))

    # UsageStore protocol ---------------------------------------------------
    def record_ai_call(self, rec: AICallRecord) -> None:
        self._x("insert into ai_calls (tenant_id, provider, model, input_tokens, output_tokens, estimated_cost, latency_ms,"
                " category, ok, created_at) values (?,?,?,?,?,?,?,?,?,?)",
                (rec.tenant_id, rec.provider, rec.model, rec.input_tokens, rec.output_tokens, rec.estimated_cost,
                 rec.latency_ms, rec.category, int(rec.ok), _iso(utcnow())))

    def ai_spend(self, tenant_id: str, period: str) -> float:
        now = utcnow()
        start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        if period == "month":
            start = start.replace(day=1)
        rows = self._q("select coalesce(sum(estimated_cost),0) s from ai_calls where tenant_id=? and created_at>=?",
                       (tenant_id, _iso(start)))
        return float(rows[0]["s"])

    def ai_spend_all(self, period: str) -> float:
        """Cloud AI spend of all customers together (the brain's monthly limit is one limit for everything)."""
        now = utcnow()
        start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        if period == "month":
            start = start.replace(day=1)
        rows = self._q("select coalesce(sum(estimated_cost),0) s from ai_calls where created_at>=?", (_iso(start),))
        return float(rows[0]["s"])

    def ai_usage(self, tenant_id: str) -> list[dict[str, Any]]:
        return [dict(r) for r in self._q(
            "select provider, model, count(*) calls, sum(input_tokens) input_tokens, sum(output_tokens) output_tokens,"
            " sum(estimated_cost) estimated_cost, avg(latency_ms) avg_latency_ms from ai_calls where tenant_id=?"
            " group by provider, model", (tenant_id,))]

    def cached_diagnosis(self, tenant_id: str, fingerprint: str) -> Diagnosis | None:
        rows = self._q("select payload, created_at from diagnosis_cache where tenant_id=? and fingerprint=?", (tenant_id, fingerprint))
        if not rows or datetime.fromisoformat(rows[0]["created_at"]) < utcnow() - timedelta(hours=6):
            return None
        return Diagnosis.model_validate_json(rows[0]["payload"])

    def cache_diagnosis(self, tenant_id: str, fingerprint: str, diagnosis: Diagnosis) -> None:
        self._x("insert or replace into diagnosis_cache (tenant_id, fingerprint, payload, created_at) values (?,?,?,?)",
                (tenant_id, fingerprint, diagnosis.model_dump_json(), _iso(utcnow())))

    # ------------------------------------------------------------------ approvals & tool runs
    def create_approval(self, tenant_id: str, tool_id: str, params_hash: str, approved_by: str, ttl_minutes: int = 30) -> str:
        aid = new_id("apr")
        self._x("insert into approvals (id, tenant_id, tool_id, params_hash, approved_by, expires_at, created_at) values (?,?,?,?,?,?,?)",
                (aid, tenant_id, tool_id, params_hash, approved_by, _iso(utcnow() + timedelta(minutes=ttl_minutes)), _iso(utcnow())))
        self.audit(approved_by, "approval.created", {"tool_id": tool_id, "approval_id": aid}, tenant_id=tenant_id)
        return aid

    def approval(self, approval_id: str, tenant_id: str) -> Approval | None:
        rows = self._q("select * from approvals where id=? and tenant_id=?", (approval_id, tenant_id))
        if not rows:
            return None
        r = rows[0]
        return Approval(approval_id=r["id"], tenant_id=r["tenant_id"], tool_id=r["tool_id"], params_hash=r["params_hash"],
                        approved_by=r["approved_by"], expires_at=datetime.fromisoformat(r["expires_at"]), used=r["used_at"] is not None)

    def consume_approval(self, approval_id: str) -> None:
        self._x("update approvals set used_at=? where id=? and used_at is null", (_iso(utcnow()), approval_id))

    def record_tool_run(self, tenant_id: str, tool_id: str) -> None:
        self._x("insert into tool_runs (tenant_id, tool_id, at) values (?,?,?)", (tenant_id, tool_id, _iso(utcnow())))

    def tool_runs_last_hour(self, tenant_id: str, tool_id: str) -> int:
        return self._q("select count(*) c from tool_runs where tenant_id=? and tool_id=? and at>=?",
                       (tenant_id, tool_id, _iso(utcnow() - timedelta(hours=1))))[0]["c"]

    # ------------------------------------------------------------------ knowledge base
    def add_knowledge(self, app_name: str, error_code: str, symptoms: str, verified_cause: str, solution_steps: str,
                      test_result: str, approved_by: str, app_version: str | None = None, risk_level: int = 0) -> int:
        """Only verified, approved, customer-neutral knowledge. Never grants repair permission."""
        with self._lock:
            cur = self._db.execute(
                "insert into knowledge (app_name, app_version, error_code, symptoms, verified_cause, solution_steps, risk_level,"
                " test_result, approved_by, created_at) values (?,?,?,?,?,?,?,?,?,?)",
                (app_name[:200], app_version, error_code[:120], symptoms[:2000], verified_cause[:2000], solution_steps[:4000],
                 risk_level, test_result[:500], approved_by[:80], _iso(utcnow())))
            kid = int(cur.lastrowid or 0)
        self.audit(approved_by, "knowledge.added", {"id": kid, "error_code": error_code[:120]})
        return kid

    def knowledge_for(self, app_name: str, error_codes: list[str]) -> list[str]:
        if not error_codes:
            return []
        marks = ",".join("?" for _ in error_codes)
        rows = self._q(f"select verified_cause, solution_steps from knowledge where lower(app_name)=lower(?) and error_code in ({marks}) limit 5",
                       (app_name, *error_codes))
        return [f"{r['verified_cause']} -> {r['solution_steps']}" for r in rows]

    # ------------------------------------------------------------------ audit (hash chain)
    def audit(self, actor: str, action: str, detail: dict[str, Any], tenant_id: str | None = None, device_id: str | None = None) -> None:
        with self._lock:
            prev = self._q("select hash from audit order by id desc limit 1")
            prev_hash = prev[0]["hash"] if prev else "0" * 64
            at = _iso(utcnow())
            body = json.dumps(detail, sort_keys=True, default=str)[:8000]
            h = hashlib.sha256("|".join([prev_hash, at, tenant_id or "", device_id or "", actor, action, body]).encode()).hexdigest()
            self._db.execute("insert into audit (at, tenant_id, device_id, actor, action, detail, prev_hash, hash) values (?,?,?,?,?,?,?,?)",
                             (at, tenant_id, device_id, actor, action, body, prev_hash, h))

    def audit_log(self, tenant_id: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        if tenant_id:
            rows = self._q("select * from audit where tenant_id=? order by id desc limit ?", (tenant_id, limit))
        else:
            rows = self._q("select * from audit order by id desc limit ?", (limit,))
        return [dict(r) for r in rows]

    def verify_audit_chain(self) -> bool:
        prev_hash = "0" * 64
        for r in self._q("select * from audit order by id asc"):
            expect = hashlib.sha256("|".join([prev_hash, r["at"], r["tenant_id"] or "", r["device_id"] or "", r["actor"],
                                              r["action"], r["detail"]]).encode()).hexdigest()
            if r["prev_hash"] != prev_hash or r["hash"] != expect:
                return False
            prev_hash = r["hash"]
        return True
