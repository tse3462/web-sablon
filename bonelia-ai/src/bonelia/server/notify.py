"""Owner notifications: important findings, repairs, missing consent, silent computers.

Channels:
* Windows toast on the home server PC (default on Windows; no extra software).
* Telegram: connected from the control panel (Settings tab) -- bot token + chat stored in the
  server database, used from the next notification on (no restart). The older env-var setup
  (BONELIA_TELEGRAM_BOT_TOKEN + telegram_chat_id in server.toml) still works.

Every message is de-duplicated by a key with a quiet period, so a repeating
problem produces one notification, not hundreds.
"""

from __future__ import annotations

import logging
import os
import re
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


TELEGRAM_KEY = "telegram"
TOKEN_RE = re.compile(r"^\d{5,12}:[A-Za-z0-9_-]{30,64}$")
_TOKEN_IN_TEXT = re.compile(r"(?<![0-9])(\d{5,12})\s*:\s*([A-Za-z0-9_-]{30,64})(?![A-Za-z0-9_-])")


def extract_token(raw: str) -> str | None:
    """Find a bot token in whatever was pasted: the token alone, the whole @BotFather message,
    or text with invisible characters that phones add when copying (zero-width, bidi marks)."""
    import unicodedata

    text = unicodedata.normalize("NFKC", raw or "")  # e.g. a full-width colon becomes ':'
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Cf")  # drop invisible format characters
    m = _TOKEN_IN_TEXT.search(text)
    return f"{m.group(1)}:{m.group(2)}" if m else None


class TelegramAPI:
    """Minimal Bot API client. Errors never include the token (it is part of the URL)."""

    BASE = "https://api.telegram.org"

    def __init__(self, transport: httpx.BaseTransport | None = None):
        self._client = httpx.Client(timeout=15.0, transport=transport)

    def call(self, token: str, method: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        try:
            r = self._client.post(f"{self.BASE}/bot{token}/{method}", json=payload or {})
            data = r.json()
        except (httpx.HTTPError, ValueError):
            return {"ok": False, "description": "unreachable"}
        return data if isinstance(data, dict) else {"ok": False, "description": "bad_reply"}

    def bot_name(self, token: str) -> str | None:
        d = self.call(token, "getMe")
        return str(d["result"].get("username") or "") if d.get("ok") and isinstance(d.get("result"), dict) else None

    def latest_chat(self, token: str) -> tuple[str, str] | None:
        """Chat id + name of the newest private message sent to the bot."""
        d = self.call(token, "getUpdates", {"timeout": 0, "allowed_updates": ["message"]})
        if not d.get("ok"):
            return None
        for upd in reversed(d.get("result") or []):
            chat = ((upd or {}).get("message") or {}).get("chat") or {}
            if chat.get("id") is not None and chat.get("type", "private") == "private":
                name = " ".join(x for x in (chat.get("first_name"), chat.get("last_name")) if x) or chat.get("username") or ""
                return str(chat["id"]), str(name)[:60]
        return None

    def send(self, token: str, chat_id: str, text: str) -> bool:
        d = self.call(token, "sendMessage", {"chat_id": chat_id, "text": text[:3500], "disable_web_page_preview": True})
        return bool(d.get("ok"))


class StoredTelegram:
    """Telegram channel configured from the panel; reads its settings on every message."""

    name = "telegram"

    def __init__(self, store, api: TelegramAPI | None = None):
        self.store, self.api = store, api or TelegramAPI()

    def _cfg(self) -> dict[str, Any] | None:
        c = self.store.get_setting(TELEGRAM_KEY) or {}
        return c if c.get("token") and c.get("chat_id") else None

    def enabled(self) -> bool:
        return self._cfg() is not None

    def send(self, title: str, body: str) -> bool:
        c = self._cfg()
        return bool(c) and self.api.send(c["token"], c["chat_id"], f"{title}\n{body}")


_T = {
    "finding": {"tr": "⚠ {customer} · {device}: önemli sorun", "de": "⚠ {customer} · {device}: wichtiges Problem"},
    "repaired": {"tr": "✅ {customer} · {device}: onarıldı", "de": "✅ {customer} · {device}: repariert"},
    "repair_failed": {"tr": "❌ {customer} · {device}: onarım başarısız", "de": "❌ {customer} · {device}: Reparatur fehlgeschlagen"},
    "denied": {"tr": "🔒 {customer} · {device}: onarım için izin gerekli", "de": "🔒 {customer} · {device}: Freigabe nötig"},
    "offline": {"tr": "📴 {customer} · {device}: 30 dakikadır sinyal yok", "de": "📴 {customer} · {device}: seit 30 Min. kein Signal"},
    "test": {"tr": "BONELİA AI test bildirimi", "de": "BONELİA AI Testbenachrichtigung"},
    "uptime_down": {"tr": "🔴 {name} çalışmıyor", "de": "🔴 {name} ist nicht erreichbar"},
    "uptime_up": {"tr": "🟢 {name} yeniden çalışıyor", "de": "🟢 {name} ist wieder erreichbar"},
    "repair_result": {"tr": "🤖 {name}: yapay zekâ incelemesi", "de": "🤖 {name}: KI-Prüfung"},
    "disk_low": {"tr": "💽 {customer} · {device}: disk dolmak üzere", "de": "💽 {customer} · {device}: Festplatte fast voll"},
    "disk_drop": {"tr": "💽 {customer} · {device}: disk hızla doluyor", "de": "💽 {customer} · {device}: Festplatte füllt sich schnell"},
    "internet_back": {"tr": "📶 Ev interneti geri geldi", "de": "📶 Internet zu Hause wieder da"},
    "ssl_expiring": {"tr": "🔐 {name}: SSL sertifikası {days} gün içinde bitiyor", "de": "🔐 {name}: SSL-Zertifikat läuft in {days} Tagen ab"},
}


class Notifier:
    def __init__(self, store, channels: list[Channel], lang: str = "tr"):
        self.store = store
        self.channels = channels
        self.lang = lang if lang in ("tr", "de") else "tr"

    def _title(self, kind: str, **kw: Any) -> str:
        return _T[kind][self.lang].format(**kw)

    def _active(self) -> list[Channel]:
        out = []
        for ch in self.channels:
            try:
                if getattr(ch, "enabled", lambda: True)():
                    out.append(ch)
            except Exception:  # a broken channel must never break the server
                continue
        return out

    def _send(self, key: str, quiet: timedelta, title: str, body: str) -> bool:
        channels = self._active()  # nothing is "used up" while no channel is set up
        if not channels or not self.store.notification_due(key, quiet):
            return False
        sent = False
        for ch in channels:
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

    _RESCUE = {  # automatic rescue (06.11.2026): plain words instead of a tool id and a process number
        "tr": {"windows.restart_hung_app": ("Donan program yeniden açıldı: {n}", "Donan program kapatılamadı: {n}"),
               "windows.close_program": ("Bellek boşaltıldı: {n} kapatılıp yeniden açıldı", "{n} kapanmadı — büyük ihtimalle kaydedilmemiş iş var, program açık bırakıldı"),
               "closed": "Bellek boşaltıldı: {n} kapatıldı"},
        "de": {"windows.restart_hung_app": ("Hängendes Programm neu gestartet: {n}", "Hängendes Programm ließ sich nicht beenden: {n}"),
               "windows.close_program": ("Speicher freigegeben: {n} geschlossen und neu geöffnet", "{n} wurde nicht geschlossen — vermutlich ungespeicherte Arbeit, Programm bleibt offen"),
               "closed": "Speicher freigegeben: {n} geschlossen"},
    }

    def repair(self, customer: str, device: str, tenant_id: str, tool_id: str, params: dict, outcome: str) -> bool:
        if tool_id in self._RESCUE["tr"]:
            T, n = self._RESCUE[self.lang], str(params.get("name") or "?")
            ok = outcome in ("executed_verified", "executed_unverified")
            text = (T["closed"] if ok and tool_id == "windows.close_program" and params.get("restart") is not True
                    else T[tool_id][0 if ok else 1]).format(n=n)
            return self._send(f"rescue|{tenant_id}|{device}|{tool_id}|{n.lower()}|{ok}", timedelta(hours=1),
                              self._title("repaired" if ok else "repair_failed", customer=customer, device=device), text)
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

    # ------------------------------------------------------------- own programs (uptime monitor)
    _REASONS = {"tr": {"timeout": "yanıt yok (zaman aşımı)", "connection": "bağlantı kurulamadı", "ssl": "SSL hatası",
                       "keyword_missing": "beklenen yanıt yok (örn. veritabanı)"},
                "de": {"timeout": "keine Antwort (Zeitüberschreitung)", "connection": "keine Verbindung", "ssl": "SSL-Fehler",
                       "keyword_missing": "erwartete Antwort fehlt (z. B. Datenbank)"}}

    def uptime_down(self, app_id: str, name: str, reason: str, links: list[dict] | None = None, repair: bool = False) -> bool:
        text = self._REASONS[self.lang].get(reason, reason.replace("http_", "HTTP "))
        # intervention links from the panel (Supabase, Cloudflare, GitHub …): one tap from the message
        text += "".join(f"\n→ {l.get('label', '')}: {l.get('url', '')}" for l in (links or [])[:6])
        if repair:
            text += ("\n\n🤖 Yapay zekâ sebebi araştırıyor; sonuç birkaç dakika içinde burada." if self.lang == "tr"
                     else "\n\n🤖 Die KI sucht die Ursache; das Ergebnis kommt in wenigen Minuten hierher.")
        return self._send(f"uptime_down|{app_id}", timedelta(minutes=5), self._title("uptime_down", name=name), text)

    _REPAIR = {
        "tr": {"fixed": "✅ Düzeltme hazır, testler geçti: {branch}\nHenüz canlıda değil. Canlıya almak için Claude'a yaz: \"{branch} canlıya al\"",
               "fix_failed_tests": "⚠️ Düzeltme denendi ama testler geçmedi ({branch}). Bu mesajı Claude'a ilet.",
               "fix_not_saved": "⚠️ Düzeltme kaydedilemedi. Bu mesajı Claude'a ilet.",
               "no_fix_external": "Sorun bizim kodda değil; kod değiştirilmedi.",
               "no_fix": "Kod değiştirilmedi.",
               "healthy_again": "Site kendiliğinden düzeldi; yapay zekâ çalıştırılmadı.",
               "no_key": "GitHub'da ANTHROPIC_API_KEY eksik; inceleme yapılamadı.",
               "timeout": "90 dakikada sonuç gelmedi. GitHub'daki Auto repair işine bak.",
               "run_failed": "Onarım işi hata verdi. Bu mesajı Claude'a ilet.",
               "other": "İnceleme bitti.", "details": "Ayrıntı"},
        "de": {"fixed": "✅ Korrektur fertig, Tests bestanden: {branch}\nNoch nicht live. Zum Live-Schalten Claude schreiben: \"{branch} live schalten\"",
               "fix_failed_tests": "⚠️ Korrektur versucht, aber Tests nicht bestanden ({branch}). Nachricht an Claude weitergeben.",
               "fix_not_saved": "⚠️ Korrektur konnte nicht gespeichert werden. Nachricht an Claude weitergeben.",
               "no_fix_external": "Das Problem liegt nicht in unserem Code; nichts geändert.",
               "no_fix": "Code nicht geändert.",
               "healthy_again": "Die Seite lief wieder von selbst; die KI wurde nicht gestartet.",
               "no_key": "ANTHROPIC_API_KEY fehlt bei GitHub; keine Prüfung.",
               "timeout": "Nach 90 Minuten kein Ergebnis. Den Auto-repair-Lauf bei GitHub ansehen.",
               "run_failed": "Der Reparatur-Lauf ist fehlgeschlagen. Nachricht an Claude weitergeben.",
               "other": "Prüfung beendet.", "details": "Details"},
    }

    def repair_result(self, app_id: str, name: str, request_id: str, report: dict) -> bool:
        """The AI's finding for one outage; the decision to go live always stays with the owner."""
        T = self._REPAIR[self.lang]
        status = str(report.get("status") or "")
        key = "no_fix_external" if status == "no_fix" and report.get("cause") == "external" else status
        line = T.get(key, T["other"]).format(branch=report.get("branch") or "?")
        summary = str(report.get("summary") or "").strip()[:600]
        body = (summary + "\n\n" if summary and status not in ("healthy_again", "no_key", "timeout") else "") + line
        if report.get("run_url"):
            body += f"\n{T['details']}: {report['run_url']}"
        return self._send(f"repair_result|{app_id}|{request_id}", timedelta(days=30), self._title("repair_result", name=name), body)

    def disk_low(self, device_id: str, customer: str, device: str, free: int, total: int) -> bool:
        gb = lambda b: f"{b / 1024 ** 3:.1f}".replace(".", "," if self.lang == "de" else ".")  # noqa: E731
        pct = round(100 * free / total) if total else 0
        body = (f"Boş: {gb(free)} GB / {gb(total)} GB (%{pct}). Panel → Bilgisayarlar → Disk: neyin yer kapladığını ve neyin silinebileceğini gösterir."
                if self.lang == "tr" else
                f"Frei: {gb(free)} GB von {gb(total)} GB ({pct} %). Panel → Computer → Festplatte zeigt, was Platz belegt und was weg kann.")
        return self._send(f"disk_low|{device_id}", timedelta(hours=23), self._title("disk_low", customer=customer, device=device), body)

    def disk_drop(self, device_id: str, customer: str, device: str, lost: int, days: int) -> bool:
        gb = f"{lost / 1024 ** 3:.0f}"
        body = (f"Son {days} günde {gb} GB azaldı. Panel → Bilgisayarlar → Disk ile nedenine bakın."
                if self.lang == "tr" else f"In {days} Tagen {gb} GB weniger frei. Panel → Computer → Festplatte zeigt den Grund.")
        return self._send(f"disk_drop|{device_id}", timedelta(days=6), self._title("disk_drop", customer=customer, device=device), body)

    def internet_back(self, minutes: int) -> bool:
        body = (f"Evdeki internet {minutes} dk kesikti; bu sürede programlar kontrol edilemedi." if self.lang == "tr"
                else f"Das Internet zu Hause war {minutes} Min. weg; in dieser Zeit wurden die Programme nicht geprüft.")
        return self._send("internet_back", timedelta(0), self._title("internet_back"), body)

    def uptime_up(self, app_id: str, name: str, minutes: int) -> bool:
        self.store.clear_notification(f"uptime_down|{app_id}")
        body = f"{minutes} dk sonra" if self.lang == "tr" else f"nach {minutes} Min."
        return self._send(f"uptime_up|{app_id}", timedelta(0), self._title("uptime_up", name=name), body)

    def ssl_expiring(self, app_id: str, name: str, days: int) -> bool:
        return self._send(f"ssl|{app_id}", timedelta(hours=23), self._title("ssl_expiring", name=name, days=days), "")

    def test(self) -> bool:
        sent = False
        for ch in self._active():
            sent = ch.send(_T["test"][self.lang], "OK") or sent
        return sent


def build_notifier(store, cfg_notify: dict[str, Any], lang: str = "tr") -> Notifier:
    channels: list[Channel] = []
    if cfg_notify.get("windows_toast", False):  # enabled in deployment/server.home.toml
        channels.append(WindowsToast())
    channels.append(StoredTelegram(store))  # set up from the panel; inactive until connected
    token = os.environ.get("BONELIA_TELEGRAM_BOT_TOKEN")
    if token and cfg_notify.get("telegram_chat_id"):
        channels.append(Telegram(token, str(cfg_notify["telegram_chat_id"])))
    return Notifier(store, channels, cfg_notify.get("language", lang))
