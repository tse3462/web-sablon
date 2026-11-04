import json

import httpx
import pytest

from bonelia.adapters import all_manifests
from bonelia.adapters.base import CAPABILITY_KEYS
from bonelia.adapters.veedelkorb import VeedelKorbAdapter, events_from_health
from bonelia.repair.builtin_tools import VeedelKorbSafeAction, veedelkorb_retry_tool
from tests.conftest import fixture_json


def test_degraded_payload_is_translated_into_events():
    evs = events_from_health(503, fixture_json("saglik_degraded.json"), "tr")
    codes = {e.rule_id for e in evs}
    assert {"veedelkorb.check:notifications", "veedelkorb.job:notify", "veedelkorb.job:invoice",
            "veedelkorb.cron.failed_1h", "veedelkorb.notifications.failed_24h", "veedelkorb.notifications.queued_old_30m",
            "veedelkorb.orders.delivery_failed"} == codes
    # healthy jobs (dispatch 40 s; backup 50 000 s < 30 h limit) are not flagged
    assert "veedelkorb.job:dispatch" not in codes and "veedelkorb.job:backup" not in codes
    assert all(e.app.app_id == "veedelkorb" for e in evs)


def test_ok_payload_gives_no_events():
    assert events_from_health(200, {"status": "ok", "checks": [], "context": {"jobs": [], "notifications": {"failed_24h": 0}}}) == []


def test_unauthorized_and_unreachable():
    assert events_from_health(401, None)[0].rule_id == "veedelkorb.unauthorized"
    assert events_from_health(0, None)[0].rule_id == "veedelkorb.unreachable"


def test_adapter_sends_token_only_in_header_and_uses_agent_context():
    seen = {}

    def handler(req: httpx.Request):
        seen["url"] = str(req.url)
        seen["auth"] = req.headers.get("authorization")
        return httpx.Response(503, json=fixture_json("saglik_degraded.json"))

    a = VeedelKorbAdapter("https://example.supabase.co", "tok-123", transport=httpx.MockTransport(handler))
    evs, st = a.health("de")
    assert seen["url"] == "https://example.supabase.co/functions/v1/saglik?context=agent"
    assert seen["auth"] == "Bearer tok-123" and "tok-123" not in seen["url"]
    assert st["veedelkorb:ai_control"] == "disabled_or_unknown" and st["veedelkorb:saglik"] == "http_503"
    assert "tok-123" not in json.dumps([e.model_dump(mode="json") for e in evs])


def test_adapter_requires_https():
    with pytest.raises(ValueError):
        VeedelKorbAdapter("http://example.com", "t")


def test_oversized_response_is_rejected():
    a = VeedelKorbAdapter("https://x.supabase.co", "t", transport=httpx.MockTransport(lambda r: httpx.Response(200, content=b"{" + b" " * 80_000 + b"}")))
    assert a.fetch() == (200, None)


def test_safe_action_executor_only_for_test_environment():
    a = VeedelKorbAdapter("https://x.supabase.co", "t", transport=httpx.MockTransport(lambda r: httpx.Response(200, json={})))
    with pytest.raises(PermissionError):
        VeedelKorbSafeAction("https://x.supabase.co", "svc", a, "production")
    assert veedelkorb_retry_tool(None).enabled is False


def test_safe_action_verification_against_controlled_test_system():
    state = {"failed_24h": 7, "rpc_calls": 0}

    def handler(req: httpx.Request):
        if req.url.path.endswith("/rpc/ai_safe_action"):
            assert json.loads(req.content)["p_action"] == "retry_failed_notifications"
            state["rpc_calls"] += 1
            state["failed_24h"] = 0
            return httpx.Response(200, json={"ok": True, "result": {"requeued": 7}})
        return httpx.Response(200, json={"status": "ok", "checks": [], "context": {"notifications": {"failed_24h": state["failed_24h"]}}})

    t = httpx.MockTransport(handler)
    act = VeedelKorbSafeAction("https://x.supabase.co", "svc", VeedelKorbAdapter("https://x.supabase.co", "tok", transport=t), "test", transport=t)
    dry = act.executor({}, True)
    assert dry.detail["failed_24h_before"] == 7 and state["rpc_calls"] == 0
    res = act.executor({}, False)
    assert res.ok and act.verifier({}, res) and res.detail["failed_24h_after"] == 0


def test_manifests_declare_all_capabilities_honestly():
    ms = {m.adapter_id: m for m in all_manifests()}
    for m in ms.values():
        assert set(m.capabilities) == set(CAPABILITY_KEYS)
    for planned in ("bonelia-finance", "vedicore", "kanslide", "sap-business-one", "sap-s4hana"):
        assert ms[planned].status == "planned" and not any(ms[planned].capabilities.values())
