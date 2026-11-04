"""Owner notifications: important findings, repairs, missing consent, silent computers.

Channels:
* Windows toast on the home server PC (default on Windows; no extra software).
* Telegram (optional): token from env BONELIA_TELEGRAM_BOT_TOKEN, chat id in server.toml.

Every message is de-duplicated by a key with a quiet period, so a repeating
problem produces one notification, not hundreds.
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
from datetime import datetime, timedelta
from typing import Any, Protocol

import httpx

from ..contracts import DiagnosticEvent, Triage, utcnow

log = logging.getLogger("bonelia.notify")

OFFLINE_AFTER = timedelta(minutes=30)


class Channel(Protocol):
    name: str

    def send(self, title: str, body: str) -> bool: ...


_TOAST_PS = r"""
$ErrorActionPreference = 'Stop'
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null
$t = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
$x = $t.GetElementsByTagName('text')
$x.Item(0).AppendChild($t.CreateTextNode($env:BN_TITLE)) > $null
$x.Item(1).AppendChild($t.CreateTextNode($env:BN_BODY)) > $null
$app = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($app).Show([Windows.UI.Notifications.ToastNotification]::new($t))
"""


class WindowsToast:
    name = "windows_toast"

    def send(self, title: str, body: str) -> bool:
        if sys.platform != "win32":
            return False
        # Text is passed through environment variables, never interpolated into the script.
        env = {**os.environ, "BN_TITLE": title[:120], "BN_BODY": body[:400]}
        try:
            p = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", _TOAST_PS], env=env,
                               capture_output=True, timeout=20, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            return p.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            return False


class Telegram:
    name = "telegram"

    def __init__(self, token: str, chat_id: str, transport: httpx.BaseTransport | None = None):
        self._url = f"https://api.telegram.org/bot{token}/sendMessage"
        self.chat_id = chat_id
        self._client = httpx.Client(timeout=10.0, transport=transport)

    def send(self, title: str, body: str) -> bool:
        try:
            r = self._client.post(self._url, json={"chat_id": self.chat_id, "text": f"{title}\n{body}"[:3500],
                                                   "disable_web_page_preview": True})
            return r.status_code == 200
        except httpx.HTTPError:
            return False


_T = {
    "finding": {"tr": "⚠ {customer} · {device}: önemli sorun", "de": "⚠ {customer} · {device}: wichtiges Problem"},
    "repaired": {"tr": "✅ {customer} · {device}: onarıldı", "de": "✅ {customer} · {device}: repariert"},
    "repair_failed": {"tr": "❌ {customer} · {device}: onarım başarısız", "de": "❌ {customer} · {device}: Reparatur fehlgeschlagen"},
    "denied": {"tr": "🔒 {customer} · {device}: onarım için izin gerekli", "de": "🔒 {customer} · {device}: Freigabe nötig"},
    "offline": {"tr": "📴 {customer} · {device}: 30 dakikadır sinyal yok", "de": "📴 {customer} · {device}: seit 30 Min. kein Signal"},
    "test": {"tr": "BONELİA AI test bildirimi", "de": "BONELİA AI Testbenachrichtigung"},
}


class Notifier:
    def __init__(self, store, channels: list[Channel], lang: str = "tr"):
        self.store = store
        self.channels = channels
        self.lang = lang if lang in ("tr", "de") else "tr"

    def _title(self, kind: str, **kw: Any) -> str:
        return _T[kind][self.lang].format(**kw)

    def _send(self, key: str, quiet: timedelta, title: str, body: str) -> bool:
        if not self.channels or not self.store.notification_due(key, quiet):
            return False
        sent = False
        for ch in self.channels:
            try:
                sent = ch.send(title, body) or sent
            except Exception as exc:  # a broken channel must never break the server
                log.warning("notification via %s failed: %s", getattr(ch, "name", "?"), exc)
        self.store.mark_notified(key)
        return sent

    def finding(self, customer: str, device: str, tenant_id: str, ev: DiagnosticEvent) -> bool:
        if ev.triage != Triage.important:
            return False
        body = ev.title + (f"\n→ {ev.repair_tool} (otomatik / automatisch)" if ev.repair_tool else "")
        return self._send(f"finding|{tenant_id}|{ev.fingerprint}", timedelta(hours=6),
                          self._title("finding", customer=customer, device=device), body)

    def repair(self, customer: str, device: str, tenant_id: str, tool_id: str, params: dict, outcome: str) -> bool:
        what = f"{tool_id} {' '.join(str(v) for v in params.values())}".strip()
        if outcome == "executed_verified":
            return self._send(f"repaired|{tenant_id}|{device}|{what}", timedelta(hours=1),
                              self._title("repaired", customer=customer, device=device), what)
        return self._send(f"repair_failed|{tenant_id}|{device}|{what}", timedelta(hours=6),
                          self._title("repair_failed", customer=customer, device=device), f"{what} → {outcome}")

    def denied(self, customer: str, device: str, tenant_id: str, tool_id: str, params: dict, reasons: list[str]) -> bool:
        what = f"{tool_id} {' '.join(str(v) for v in params.values())}".strip()
        return self._send(f"denied|{tenant_id}|{device}|{what}", timedelta(hours=24),
                          self._title("denied", customer=customer, device=device), f"{what} ({', '.join(reasons)})")

    def check_offline(self, now: datetime | None = None) -> list[str]:
        """Notify once per silent agent; re-armed when it reports again."""
        now = now or utcnow()
        names = {t["id"]: t["name"] for t in self.store.tenants()}
        out = []
        for d in self.store.devices():
            if d["status"] != "active" or '"agent"' not in str(d["scopes"]) or not d.get("last_seen_at"):
                continue
            key = f"offline|{d['id']}"
            if now - datetime.fromisoformat(d["last_seen_at"]) < OFFLINE_AFTER:
                self.store.clear_notification(key)  # back online: next silence notifies again
                continue
            if self._send(key, timedelta(days=3650), self._title("offline", customer=names.get(d["tenant_id"], "?"),
                                                                    device=d["label"]), d["last_seen_at"][:16]):
                out.append(d["id"])
        return out

    def test(self) -> bool:
        sent = False
        for ch in self.channels:
            sent = ch.send(_T["test"][self.lang], "OK") or sent
        return sent


def build_notifier(store, cfg_notify: dict[str, Any], lang: str = "tr") -> Notifier:
    channels: list[Channel] = []
    if cfg_notify.get("windows_toast", False):  # enabled in deployment/server.home.toml
        channels.append(WindowsToast())
    token = os.environ.get("BONELIA_TELEGRAM_BOT_TOKEN")
    if token and cfg_notify.get("telegram_chat_id"):
        channels.append(Telegram(token, str(cfg_notify["telegram_chat_id"])))
    return Notifier(store, channels, cfg_notify.get("language", lang))
