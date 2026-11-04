"""BONELİA AI — optional VeedelKorb adapter (server-side, READ-ONLY).

This package is NOT part of the BONELİA AI core. It is discovered through the
`bonelia.adapters` entry point and may be uninstalled at any time; the core keeps
working without it. It imports only `bonelia.plugin_api`.

It never changes VeedelKorb's source code, database or live services:

* Reads VeedelKorb's existing `saglik` Edge Function with `?context=agent`
  (contract verified in tse3462/veedelkorb, supabase/functions/_shared/health.mjs,
  2026-11-04): aggregated, personal-data-free counters only.
* The health token is a server-side secret (`BONELIA_VEEDELKORB_HEALTH_TOKEN`);
  it is never sent to, or stored on, a USB device.
* The optional `veedelkorb.retry_failed_notifications` tool wraps VeedelKorb's own
  allow-listed `ai_safe_action` RPC. It can only be configured for a separate TEST
  project, is disabled by default and must be enabled explicitly by the owner.
"""

from __future__ import annotations

import hashlib
from typing import Any, Mapping

import httpx

from bonelia.plugin_api import (
    AdapterManifest, AppIdentity, DiagnosticEvent, ErrorCategory, Evidence, ExecResult, RiskLevel, ServerAdapter,
    Severity, ToolSpec, redact_value,
)

__version__ = "0.1.0"

ENV_TOKEN = "BONELIA_VEEDELKORB_HEALTH_TOKEN"
ENV_TEST_SERVICE_KEY = "BONELIA_VEEDELKORB_TEST_SERVICE_KEY"

MANIFEST = AdapterManifest(
    adapter_id="veedelkorb",
    name="VeedelKorb",
    version=__version__,
    status="implemented",
    runs_on="server",
    capabilities={
        "recognize": True, "version_check": False, "find_logs": False, "api_connection": True,
        "health_check": True, "read_only_ops": True, "safe_interventions": False, "intervention_verification": True,
    },
    supported_app_versions="saglik Edge Function v6+ (context=agent); ai_alarm_context migration 20261026150821",
    required_permissions=["HEALTH_CHECK_TOKEN of the target VeedelKorb environment (server-side secret)"],
    safe_tools=["veedelkorb.retry_failed_notifications (disabled by default, TEST environment only)"],
    notes="Optional, read-only. Accesses only aggregated counters, never customer, order or payment rows.",
    secret_env=[ENV_TOKEN, ENV_TEST_SERVICE_KEY],
)

APP = AppIdentity(app_id="veedelkorb", name="VeedelKorb", publisher="BONELIA", adapter_id="veedelkorb", recognized=True)

# Seconds without a successful run before a job is flagged. Initial values; tune with real data.
JOB_MAX_OK_AGE_S = {
    "dispatch": 15 * 60, "scheduled_tick": 15 * 60, "payment": 30 * 60, "payment_jobs": 30 * 60,
    "notify": 30 * 60, "invoice": 6 * 3600, "retention": 36 * 3600, "backup": 30 * 3600,
}

_CHECK_CATEGORY = {
    "database": ErrorCategory.database, "cron": ErrorCategory.scheduled_job, "notifications": ErrorCategory.notification,
    "payments": ErrorCategory.payment, "invoices": ErrorCategory.invoice, "backup": ErrorCategory.scheduled_job,
    "configuration": ErrorCategory.configuration,
}

_T = {
    "unreachable": {"tr": "VeedelKorb sağlık servisine ulaşılamıyor", "de": "VeedelKorb-Gesundheitsdienst nicht erreichbar",
                    "en": "VeedelKorb health service unreachable"},
    "unauthorized": {"tr": "VeedelKorb sağlık anahtarı geçersiz (401)", "de": "VeedelKorb-Health-Token ungültig (401)",
                     "en": "VeedelKorb health token rejected (401)"},
    "check": {"tr": "VeedelKorb sağlık kontrolü başarısız: {name}", "de": "VeedelKorb-Prüfung fehlgeschlagen: {name}",
              "en": "VeedelKorb health check failed: {name}"},
    "job": {"tr": "Zamanlanmış görev gecikti: {job}", "de": "Geplanter Job verspätet: {job}", "en": "Scheduled job overdue: {job}"},
    "cron": {"tr": "Son 1 saatte başarısız cron çalışması: {n}", "de": "Fehlgeschlagene Cron-Läufe (1 h): {n}",
             "en": "Failed cron runs in the last hour: {n}"},
    "notif": {"tr": "Son 24 saatte başarısız bildirim: {n}", "de": "Fehlgeschlagene Benachrichtigungen (24 h): {n}",
              "en": "Failed notifications in the last 24 h: {n}"},
    "notif_old": {"tr": "30 dakikadan eski bekleyen bildirim: {n}", "de": "Wartende Benachrichtigungen älter als 30 min: {n}",
                  "en": "Notifications queued for more than 30 min: {n}"},
    "pay": {"tr": "İlgilenilmesi gereken ödeme: {n}", "de": "Zahlungen mit Handlungsbedarf: {n}", "en": "Payments needing attention: {n}"},
    "inv": {"tr": "Teslim edilmiş ama faturası oluşmamış sipariş: {n}", "de": "Gelieferte Bestellungen ohne Rechnung: {n}",
            "en": "Delivered orders without invoice: {n}"},
    "sup": {"tr": "15 dakikadan uzun toptancı onayı bekleyen sipariş: {n}", "de": "Bestellungen >15 min ohne Händlerbestätigung: {n}",
            "en": "Orders waiting >15 min for supplier: {n}"},
    "deliv": {"tr": "Teslimatı başarısız sipariş: {n}", "de": "Bestellungen mit fehlgeschlagener Lieferung: {n}",
              "en": "Orders with failed delivery: {n}"},
}


def _fp(*parts: str) -> str:
    return hashlib.sha256("|".join(("veedelkorb",) + parts).encode()).hexdigest()[:32]


def _event(title: str, category: ErrorCategory, severity: Severity, code: str, data: dict[str, Any], fp: str) -> DiagnosticEvent:
    return DiagnosticEvent(app=APP, category=category, severity=severity, title=title, fingerprint=fp,
                           rule_id=f"veedelkorb.{code}",
                           evidence=[Evidence(source="veedelkorb:saglik", kind="health_check", code=code,
                                              data=redact_value(data), redacted=True)])


def events_from_health(status_code: int, body: dict[str, Any] | None, lang: str = "tr") -> list[DiagnosticEvent]:
    """Pure function: translate a `saglik?context=agent` response into BONELİA events."""
    lang = lang if lang in ("tr", "de", "en") else "en"
    t = lambda k, **kw: _T[k][lang].format(**kw)  # noqa: E731
    if status_code == 401:
        return [_event(t("unauthorized"), ErrorCategory.configuration, Severity.error, "unauthorized", {}, _fp("401"))]
    if not isinstance(body, dict):
        return [_event(t("unreachable"), ErrorCategory.connectivity, Severity.critical, "unreachable",
                       {"http_status": status_code}, _fp("unreachable"))]
    out: list[DiagnosticEvent] = []
    for chk in (body.get("checks") or [])[:50]:
        name = str(chk.get("name", "unknown"))[:64]
        sev = Severity.critical if name in ("database", "configuration") else Severity.error
        cat = next((c for k, c in _CHECK_CATEGORY.items() if k in name), ErrorCategory.unknown)
        out.append(_event(t("check", name=name), cat, sev, f"check:{name}", {"reason": chk.get("reason"), "http_status": status_code},
                          _fp("check", name)))
    ctx = body.get("context") or {}
    for job in (ctx.get("jobs") or [])[:25]:
        name = str(job.get("job", ""))[:64]
        age = job.get("ok_age_s")
        limit = JOB_MAX_OK_AGE_S.get(name)
        if limit and (age is None or age > limit):
            out.append(_event(t("job", job=name), ErrorCategory.scheduled_job, Severity.error, f"job:{name}",
                              {"ok_age_s": age, "expected_max_s": limit, "errors": job.get("errors")}, _fp("job", name)))
    counters = [
        ("cron", "failed_1h", "cron", ErrorCategory.scheduled_job, Severity.error),
        ("notifications", "failed_24h", "notif", ErrorCategory.notification, Severity.warning),
        ("notifications", "queued_old_30m", "notif_old", ErrorCategory.notification, Severity.warning),
        ("payments", "attention", "pay", ErrorCategory.payment, Severity.error),
        ("invoices", "pending", "inv", ErrorCategory.invoice, Severity.warning),
        ("orders", "waiting_supplier_15m", "sup", ErrorCategory.order, Severity.warning),
        ("orders", "delivery_failed", "deliv", ErrorCategory.order, Severity.warning),
    ]
    for group, key, tkey, cat, sev in counters:
        n = (ctx.get(group) or {}).get(key)
        if isinstance(n, (int, float)) and not isinstance(n, bool) and n > 0:
            out.append(_event(t(tkey, n=int(n)), cat, sev, f"{group}.{key}", {key: n}, _fp(group, key)))
    return out


class VeedelKorbAdapter(ServerAdapter):
    manifest = MANIFEST

    def __init__(self, base_url: str, token: str, transport: httpx.BaseTransport | None = None, timeout_s: float = 15.0,
                 safe_action: "VeedelKorbSafeAction | None" = None):
        if not base_url.startswith("https://") and not base_url.startswith("http://127.0.0.1"):
            raise ValueError("VeedelKorb health URL must use https")
        self.url = base_url.rstrip("/")
        self._token = token
        self._client = httpx.Client(timeout=timeout_s, transport=transport)
        self.safe_action = safe_action

    def fetch(self) -> tuple[int, dict[str, Any] | None]:
        try:
            r = self._client.get(f"{self.url}/functions/v1/saglik", params={"context": "agent"},
                                 headers={"Authorization": f"Bearer {self._token}"})
        except httpx.HTTPError:
            return 0, None
        if len(r.content) > 70_000:
            return r.status_code, None
        try:
            return r.status_code, r.json()
        except ValueError:
            return r.status_code, None

    def health(self, lang: str = "tr") -> tuple[list[DiagnosticEvent], dict[str, str]]:
        status, body = self.fetch()
        events = events_from_health(status, body, lang)
        ai_enabled = ((body or {}).get("context") or {}).get("ai_control", {}).get("enabled") if isinstance(body, dict) else None
        st = {"veedelkorb:saglik": f"http_{status}" if status else "error:unreachable",
              "veedelkorb:ai_control": "enabled" if ai_enabled else "disabled_or_unknown"}
        return events, st

    def tools(self) -> list[ToolSpec]:
        return [retry_tool(self.safe_action)]


class VeedelKorbSafeAction:
    """VeedelKorb's own `ai_safe_action('retry_failed_notifications')`. TEST environment only."""

    def __init__(self, supabase_url: str, service_key: str, health: VeedelKorbAdapter, environment: str,
                 transport: httpx.BaseTransport | None = None):
        if environment != "test":
            raise PermissionError("VeedelKorb repair executor may only be configured for a TEST environment")
        self.url = supabase_url.rstrip("/")
        self._key = service_key
        self.health = health
        self._client = httpx.Client(timeout=20.0, transport=transport)

    def _failed_24h(self) -> int | None:
        _, body = self.health.fetch()
        if not isinstance(body, dict):
            return None
        n = ((body.get("context") or {}).get("notifications") or {}).get("failed_24h")
        return int(n) if isinstance(n, (int, float)) else None

    def executor(self, params: dict[str, Any], dry_run: bool) -> ExecResult:
        before = self._failed_24h()
        if dry_run:
            return ExecResult(True, {"failed_24h_before": before, "would_requeue_max": 50,
                                     "rpc": "ai_safe_action('retry_failed_notifications')"})
        r = self._client.post(f"{self.url}/rest/v1/rpc/ai_safe_action",
                              headers={"apikey": self._key, "Authorization": f"Bearer {self._key}"},
                              json={"p_action": "retry_failed_notifications", "p_note": "BONELIA AI gateway"})
        try:
            body = r.json()
        except ValueError:
            body = {}
        ok = r.status_code == 200 and isinstance(body, dict) and body.get("ok") is not False
        return ExecResult(ok, {"http_status": r.status_code, "failed_24h_before": before,
                               "result": body if isinstance(body, dict) else {}})

    def verifier(self, params: dict[str, Any], result: ExecResult) -> bool:
        before = result.detail.get("failed_24h_before")
        after = self._failed_24h()
        result.detail["failed_24h_after"] = after
        return before is not None and after is not None and after < before


def retry_tool(action: VeedelKorbSafeAction | None) -> ToolSpec:
    return ToolSpec(
        tool_id="veedelkorb.retry_failed_notifications",
        description="Re-queue notifications that failed in the last 24 h (each at most once; VeedelKorb's own safe action)",
        platforms=("server",), risk_level=RiskLevel.SAFE_AUTO, required_scope="repair:veedelkorb", required_role="operator",
        params={}, supports_dry_run=True, idempotent=True,
        rollback="Not needed: notifications are re-queued once (ai_retried flag); no order/payment data is touched",
        timeout_s=30, max_runs_per_hour=3,
        verification="notifications.failed_24h from saglik?context=agent decreases after execution",
        side_effects="Customers may receive a previously failed notification",
        executor=action.executor if action else None, verifier=action.verifier if action else None, enabled=False)


class _Plugin:
    manifest = MANIFEST

    def create(self, config: Mapping[str, Any], env: Mapping[str, str]) -> VeedelKorbAdapter | None:
        url, token = config.get("url"), env.get(ENV_TOKEN)
        if not url or not token:
            return None  # not configured: the core reports "not_configured" and continues
        adapter = VeedelKorbAdapter(str(url), token)
        svc = env.get(ENV_TEST_SERVICE_KEY)
        if svc and config.get("environment") == "test":
            adapter.safe_action = VeedelKorbSafeAction(str(url), svc, adapter, "test")
        return adapter


PLUGIN = _Plugin()
