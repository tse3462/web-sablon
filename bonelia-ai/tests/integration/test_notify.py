"""Owner notifications: de-duplicated, never breaking the server, wired to findings/repairs/offline."""

from datetime import timedelta

import httpx

from bonelia.contracts import AppIdentity, DiagnosticEvent, Triage, utcnow
from bonelia.server.notify import Notifier, Telegram
from bonelia.server.store import Store


class FakeChannel:
    name = "fake"

    def __init__(self):
        self.sent = []

    def send(self, title, body):
        self.sent.append((title, body))
        return True


class BrokenChannel:
    name = "broken"

    def send(self, title, body):
        raise RuntimeError("network down")


def ev(fp, triage=Triage.important, title="Hizmet durmuş: Druckwarteschlange"):
    return DiagnosticEvent(app=AppIdentity(app_id="a", name="a"), title=title, fingerprint=fp, triage=triage,
                           repair_tool="windows.start_service")


def test_findings_are_deduplicated_and_harmless_never_sent(tmp_path):
    ch = FakeChannel()
    n = Notifier(Store(tmp_path / "db"), [BrokenChannel(), ch])
    assert n.finding("Filiale", "KASSE-1", "t1", ev("f1"))
    assert not n.finding("Filiale", "KASSE-1", "t1", ev("f1"))  # same problem within 6 h: silent
    assert not n.finding("Filiale", "KASSE-1", "t1", ev("f2", Triage.harmless))
    assert n.finding("Filiale", "KASSE-1", "t1", ev("f3"))
    assert len(ch.sent) == 2 and "Filiale" in ch.sent[0][0] and "KASSE-1" in ch.sent[0][0]


def test_repairs_denials_and_offline(tmp_path):
    store = Store(tmp_path / "db")
    ch = FakeChannel()
    n = Notifier(store, [ch], lang="de")
    assert n.repair("Filiale", "KASSE-1", "t1", "windows.start_service", {"service_name": "Spooler"}, "executed_verified")
    assert n.repair("Filiale", "KASSE-1", "t1", "windows.clean_temp", {}, "failed")
    assert n.denied("Filiale", "KASSE-1", "t1", "windows.restart_service", {"service_name": "X"}, ["tenant_level_exceeded"])
    assert not n.denied("Filiale", "KASSE-1", "t1", "windows.restart_service", {"service_name": "X"}, ["tenant_level_exceeded"])
    t = store.create_tenant("Filiale")
    usb = store.redeem_enrollment(store.create_enrollment_code(t, ["diagnose"]), "USB", "pk0")["device_id"]
    agent = store.create_agent_device(t, "KASSE-1", "pk1", usb)["device_id"]
    store._x("update devices set last_seen_at=? where id=?", ((utcnow() - timedelta(hours=1)).isoformat(), agent))
    assert n.check_offline() == [agent]
    assert n.check_offline() == []  # once per silence
    store.touch_device(agent)
    assert n.check_offline() == []  # back online re-arms
    store._x("update devices set last_seen_at=? where id=?", ((utcnow() - timedelta(hours=1)).isoformat(), agent))
    assert n.check_offline() == [agent]
    assert any("Signal" in s[0] for s in ch.sent)


def test_telegram_channel_protocol():
    seen = {}

    def handler(req):
        seen["url"], seen["body"] = str(req.url), req.content.decode()
        return httpx.Response(200, json={"ok": True})

    assert Telegram("123:abc", "42", transport=httpx.MockTransport(handler)).send("Titel", "Text")
    assert seen["url"] == "https://api.telegram.org/bot123:abc/sendMessage" and '"chat_id": "42"' in seen["body"].replace('":"', '": "')
    assert not Telegram("t", "1", transport=httpx.MockTransport(lambda r: httpx.Response(500))).send("a", "b")


def test_server_notifies_on_important_finding_and_on_repair(tmp_path):
    from bonelia.monitor.client import ServerClient, enroll
    from bonelia.repair.tools import ExecResult
    from bonelia.monitor.repair_local import repair
    from bonelia.security import crypto
    from bonelia.server.app import create_app
    from bonelia.server.config import ServerConfig
    from tests.conftest import ServerThread

    cfg = ServerConfig(data_dir=tmp_path / "srv", ollama_url=None)
    cfg.data_dir.mkdir()
    store = Store(cfg.db_path)
    t = store.create_tenant("Filiale Ehrenfeld")
    store.update_tenant(t, max_auto_level=1, auto_tools=["windows.start_service"])
    ch = FakeChannel()
    with ServerThread(create_app(cfg, store=store, adapters={}, server_key=crypto.generate_keypair(),
                                 notifier=Notifier(store, [ch]))) as srv:
        c = ServerClient(enroll(srv.url, store.create_enrollment_code(t, ["diagnose", "repair:windows"]), "KASSE-1"))
        c.analyze([ev("f1"), ev("f2", Triage.harmless)], None, False, "tr")
        r = repair(c, "windows.start_service", {"service_name": "Spooler"}, False,
                   {"windows.start_service": (lambda p, d: ExecResult(True, {}), lambda p, res: True)})
        assert r["outcome"] == "executed_verified"
    titles = [s[0] for s in ch.sent]
    assert any("önemli sorun" in x for x in titles) and any("onarıldı" in x for x in titles)
    assert len(titles) == 2  # harmless finding produced no notification


def test_program_down_message_carries_intervention_links_and_internet_back(tmp_path):
    ch = FakeChannel()
    n = Notifier(Store(tmp_path / "db"), [ch])
    links = [{"label": "Supabase", "url": "https://supabase.com/dashboard/project/abc"}]
    assert n.uptime_down("res", "Reservierung", "http_503", links)
    title, body = ch.sent[-1]
    assert "Reservierung" in title and "HTTP 503" in body
    assert "→ Supabase: https://supabase.com/dashboard/project/abc" in body  # one tap from Telegram
    assert n.internet_back(12)
    assert "12 dk" in ch.sent[-1][1] and "📶" in ch.sent[-1][0]


def test_ai_repair_messages_say_what_happened_and_who_decides(tmp_path):
    ch = FakeChannel()
    n = Notifier(Store(tmp_path / "db"), [ch])
    assert n.uptime_down("res", "Reservierung", "http_503", [], True)
    assert "🤖" in ch.sent[-1][1]  # the owner knows the AI is already looking
    fixed = {"status": "fixed", "cause": "code", "summary": "Son değişiklik geri alındı.", "branch": "claude/auto-repair-77",
             "run_url": "https://github.com/o/res/actions/runs/77"}
    assert n.repair_result("res", "Reservierung", "r1", fixed)
    title, body = ch.sent[-1]
    assert "Reservierung" in title and "Son değişiklik geri alındı." in body
    assert "claude/auto-repair-77" in body and "canlıya al" in body and "runs/77" in body
    assert not n.repair_result("res", "Reservierung", "r1", fixed)  # one message per AI run
    n.repair_result("res", "Reservierung", "r2", {"status": "no_fix", "cause": "external", "summary": "Supabase arızalı."})
    assert "bizim kodda değil" in ch.sent[-1][1]
    n.repair_result("res", "Reservierung", "r3", {"status": "fix_failed_tests", "cause": "code", "summary": "x", "branch": "claude/auto-repair-9"})
    assert "testler geçmedi" in ch.sent[-1][1] and "canlıya al" not in ch.sent[-1][1]
    for status in ("healthy_again", "no_key", "timeout", "run_failed", "fix_not_saved", "weird"):
        assert n.repair_result("res", "Reservierung", "s-" + status, {"status": status, "summary": "s"})
    de = Notifier(Store(tmp_path / "db2"), [ch], lang="de")
    de.repair_result("res", "Reservierung", "d1", fixed)
    assert "KI" in ch.sent[-1][0] and "live" in ch.sent[-1][1].lower()
