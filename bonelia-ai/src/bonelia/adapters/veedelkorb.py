"""VeedelKorb adapter (server-side, READ-ONLY in v0.1).

Verified against the VeedelKorb repository (tse3462/veedelkorb, 2026-11-04):
* Edge Function `saglik` (supabase/functions/_shared/health.mjs): GET with
  `Authorization: Bearer <HEALTH_CHECK_TOKEN>`; `?context=agent` adds the output of
  `public.ai_alarm_context()` — a personal-data-free summary (jobs, cron, orders,
  notifications, payments, invoices counters, ai_control.enabled).
* Status 200 = ok, 503 = degraded/unavailable, 401 = bad token.

The token lives ONLY in the server environment (`BONELIA_VEEDELKORB_HEALTH_TOKEN`).
It is never sent to, or stored on, a USB device.

`ai_safe_action` (allow-listed RPC in VeedelKorb) is registered as a tool but is
DISABLED: AI control was found switched off in production and must not be enabled
without the owner's explicit approval.
"""

from __future__ import annotations

import hashlib
from typing import Any

import httpx

from ..contracts import AppIdentity, DiagnosticEvent, ErrorCategory, Evidence, Severity
from ..security.redact import redact_value
from .base import Adapter, AdapterManifest

MANIFEST = AdapterManifest(
    adapter_id="veedelkorb",
    name="VeedelKorb",
    version="0.1.0",
    status="implemented",
    runs_on="server",
    capabilities={
        "recognize": True, "version_check": False, "find_logs": False, "api_connection": True,
        "health_check": True, "read_only_ops": True, "safe_interventions": False, "intervention_verification": True,
    },
    supported_app_versions="saglik Edge Function v6+ (context=agent); ai_alarm_context migration 20261026150821",
    required_permissions=["HEALTH_CHECK_TOKEN of the target VeedelKorb environment (server-side secret)"],
    safe_tools=["veedelkorb.retry_failed_notifications (disabled)"],
    notes="Read-only. Does not access customer, order or payment rows — only aggregated counters.",
)

APP = AppIdentity(app_id="veedelkorb", name="VeedelKorb", publisher="BONELIA", adapter_id="veedelkorb", recognized=True)

# Job heartbeat expectations (seconds without a successful run before we flag it).
# Conservative defaults; tune per environment. Source of job names: ai_alarm_context().
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
    """Pure function: translate a `saglik?context=agent` response into events."""
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


class VeedelKorbAdapter(Adapter):
    manifest = MANIFEST

    def __init__(self, base_url: str, token: str, transport: httpx.BaseTransport | None = None, timeout_s: float = 15.0):
        if not base_url.startswith("https://") and not base_url.startswith("http://127.0.0.1"):
            raise ValueError("VeedelKorb health URL must use https")
        self.url = base_url.rstrip("/")
        self._token = token
        self._client = httpx.Client(timeout=timeout_s, transport=transport)

    def recognize(self, apps: list[AppIdentity]) -> list[AppIdentity]:
        return [APP]

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

    def health(self, lang: str = "tr") -> tuple[list[DiagnosticEvent], dict[str, str]]:  # type: ignore[override]
        status, body = self.fetch()
        events = events_from_health(status, body, lang)
        ai_enabled = ((body or {}).get("context") or {}).get("ai_control", {}).get("enabled") if isinstance(body, dict) else None
        st = {"veedelkorb:saglik": f"http_{status}" if status else "error:unreachable",
              "veedelkorb:ai_control": "enabled" if ai_enabled else "disabled_or_unknown"}
        return events, st
