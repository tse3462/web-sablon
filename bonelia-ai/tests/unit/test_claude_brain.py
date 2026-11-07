"""The "brain" (user request 07.11.2026): important problems are explained by Claude, everything else stays on the free
local model; a monthly limit over all customers (5 EUR by default) and per-customer consent are always checked."""

from types import SimpleNamespace as NS

import pytest

from bonelia.ai.claude import ClaudeProvider, claude_prices
from bonelia.ai.costs import PriceTable
from bonelia.ai.providers import ProviderError
from bonelia.ai.router import HybridRouter, TenantAIPolicy
from bonelia.contracts import Triage
from tests.unit.test_ai import GOOD, FakeProvider, MemUsage, events


class FakeMessages:
    def __init__(self, reply=None, error=None):
        self.kw, self.reply, self.error = [], reply, error

    def create(self, **kw):
        self.kw.append(kw)
        if self.error:
            raise self.error
        return self.reply or NS(stop_reason="end_turn", content=[NS(type="thinking", thinking=""), NS(type="text", text=GOOD)],
                                usage=NS(input_tokens=3200, output_tokens=900), model=kw["model"])


def provider(model="claude-opus-5-5", **kw):
    msgs = FakeMessages(**kw)
    return ClaudeProvider("sk-ant-test", model=model, client=NS(beta=NS(messages=msgs))), msgs


def test_claude_is_asked_with_effort_and_refusal_fallbacks_and_only_text_is_read():
    p, msgs = provider()
    res = p.complete("system", "user")
    kw = msgs.kw[0]
    assert kw["model"] == "claude-opus-5-5" and kw["system"] == "system" and kw["messages"][0]["content"] == "user"
    assert kw["output_config"] == {"effort": "medium"} and "thinking" not in kw and "temperature" not in kw
    assert kw["fallbacks"] == "default" and kw["betas"] == ["server-side-fallback-2026-07-01"]
    assert res.text == GOOD and res.input_tokens == 3200 and res.output_tokens == 900
    assert p.name == "anthropic" and p.is_cloud


def test_haiku_has_no_server_side_fallback():
    p, msgs = provider("claude-haiku-5-5")
    p.complete("s", "u")
    assert "fallbacks" not in msgs.kw[0] and "betas" not in msgs.kw[0]


def test_a_refusal_or_an_api_error_falls_back_to_rules():
    p, _ = provider(reply=NS(stop_reason="refusal", content=[], usage=NS(input_tokens=10, output_tokens=0), model="x"))
    with pytest.raises(ProviderError):
        p.complete("s", "u")
    import anthropic
    p2, _ = provider(error=anthropic.APIConnectionError(request=__import__("httpx").Request("POST", "https://api.anthropic.com")))
    with pytest.raises(ProviderError):
        p2.complete("s", "u")
    with pytest.raises(ValueError):
        ClaudeProvider("", client=NS())


def test_prices_cover_the_selectable_models():
    t = PriceTable(claude_prices())
    assert t.estimate("anthropic", "claude-opus-5-5", 1_000_000, 0, True) == 4.0
    assert t.estimate("anthropic", "claude-sonnet-5-5", 0, 1_000_000, True) == 10.0
    assert t.estimate("anthropic", "claude-haiku-5-5", 1_000_000, 1_000_000, True) == 0.6


class AllUsage(MemUsage):
    def ai_spend_all(self, period):
        return self.spend


def brain_router(brain, local=None, usage=None, limit=5.0):
    return HybridRouter(local, None, PriceTable(claude_prices()), usage or AllUsage(), lambda: {"generic.collect_snapshot"},
                        brain=lambda: (brain, limit) if brain else None)


def important(evs):
    return [e.model_copy(update={"triage": Triage.important}) for e in evs]


def test_important_problems_go_to_the_brain_and_the_local_model_is_skipped():
    brain = FakeProvider("anthropic", cloud=True)
    brain.model = "claude-opus-5-5"
    local = FakeProvider("ollama")
    res = brain_router(brain, local).analyze(important(events()), TenantAIPolicy("t1", cloud_allowed=True), allow_cloud=False)
    assert brain.calls == len(res.diagnoses) and local.calls == 0
    assert "brain" in res.mode and res.diagnoses[0].produced_by == "anthropic:claude-opus-5-5"


def test_without_customer_consent_or_over_the_limit_the_brain_is_not_used():
    brain = FakeProvider("anthropic", cloud=True)
    brain.model = "claude-opus-5-5"
    local = FakeProvider("ollama")
    brain_router(brain, local).analyze(important(events()), TenantAIPolicy("t1", cloud_allowed=False), allow_cloud=False)
    assert brain.calls == 0 and local.calls > 0
    usage = AllUsage()
    usage.spend = 4.99  # the next call could pass 5 EUR
    res = brain_router(brain, local, usage=usage).analyze(important(events()), TenantAIPolicy("t1", cloud_allowed=True), allow_cloud=False)
    assert brain.calls == 0 and any("bütçe" in n or "Budget" in n for n in res.notices)


def test_routine_problems_stay_local_and_a_failing_brain_falls_back():
    brain = FakeProvider("anthropic", cloud=True)
    brain.model = "claude-opus-5-5"
    local = FakeProvider("ollama")
    routine = [e.model_copy(update={"triage": Triage.check}) for e in events()]
    brain_router(brain, local).analyze(routine, TenantAIPolicy("t1", cloud_allowed=True), allow_cloud=False)
    assert brain.calls == 0
    bad = FakeProvider("anthropic", cloud=True, fail=True)
    bad.model = "claude-opus-5-5"
    res = brain_router(bad, FakeProvider("ollama")).analyze(important(events()), TenantAIPolicy("t1", cloud_allowed=True), allow_cloud=False)
    assert res.diagnoses and "local" in res.mode  # Claude failed: the local model answered instead


def test_the_real_sdk_sends_model_effort_and_fallback_as_intended():
    import json

    import anthropic
    import httpx2

    seen = {}

    def handler(req):
        seen["beta"], seen["body"] = req.headers.get("anthropic-beta"), json.loads(req.content)
        return httpx2.Response(200, json={"id": "msg_1", "type": "message", "role": "assistant", "model": "claude-opus-5-5",
                                          "content": [{"type": "thinking", "thinking": "", "signature": "s"}, {"type": "text", "text": GOOD}],
                                          "stop_reason": "end_turn", "stop_sequence": None, "usage": {"input_tokens": 12, "output_tokens": 34}})

    client = anthropic.Anthropic(api_key="sk-ant-test", http_client=anthropic.DefaultHttpxClient(transport=httpx2.MockTransport(handler)))
    res = ClaudeProvider("sk-ant-test", client=client).complete("sys", "usr")
    assert res.text == GOOD and (res.input_tokens, res.output_tokens) == (12, 34)
    assert seen["beta"] == "server-side-fallback-2026-07-01"
    assert seen["body"]["fallbacks"] == "default" and seen["body"]["output_config"] == {"effort": "medium"}
    assert seen["body"]["model"] == "claude-opus-5-5" and "temperature" not in seen["body"]
