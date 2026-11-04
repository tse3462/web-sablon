import json

import httpx
import pytest

from bonelia.ai.costs import Price, PriceTable
from bonelia.ai.prompting import build_prompt, parse_diagnosis
from bonelia.ai.providers import OllamaProvider, OpenAICompatibleProvider, ProviderError, ProviderResult
from bonelia.ai.router import HybridRouter, TenantAIPolicy
from bonelia.collectors.windows_events import parse_rendered_events
from bonelia.diagnostics.engine import event_from_raw, group_events
from tests.conftest import fixture_text

GOOD = json.dumps({"summary": "Druckertreiber verursacht Absturz", "hypotheses": [
    {"cause": "printdrv.dll access violation", "confidence": "medium", "supporting_evidence": ["Application Error/1000"]}],
    "missing_information": ["Druckermodell"], "recommendations": [
        {"description": "Druckertreiber aktualisieren", "tool_id": None, "manual": True},
        {"description": "Run powershell Remove-Item C:\\ -Recurse", "tool_id": "powershell.run", "manual": False}]})


def events():
    raw = parse_rendered_events(fixture_text("app_error_events.xml"), "Application")
    return group_events([e for e in (event_from_raw(r, "de") for r in raw) if e])


class FakeProvider:
    def __init__(self, name="fake", text=GOOD, fail=False, cloud=False, avail=True):
        self.name, self.model, self.is_cloud = name, "m1", cloud
        self.text, self.fail, self.avail, self.calls, self.prompts = text, fail, avail, 0, []

    def available(self):
        return self.avail

    def complete(self, system, user, max_output_tokens=900):
        self.calls += 1
        self.prompts.append((system, user))
        if self.fail:
            raise ProviderError("boom")
        return ProviderResult(self.text, 1000, 200, 5, self.model)


class MemUsage:
    def __init__(self):
        self.calls, self.cache, self.spend = [], {}, 0.0

    def record_ai_call(self, rec):
        self.calls.append(rec)
        self.spend += rec.estimated_cost or 0

    def ai_spend(self, tenant_id, period):
        return self.spend

    def cached_diagnosis(self, t, fp):
        return self.cache.get((t, fp))

    def cache_diagnosis(self, t, fp, d):
        self.cache[(t, fp)] = d


def test_prompt_fences_untrusted_evidence_and_lists_tools():
    ev = next(e for e in events() if e.app.name == "CustomVendorApp")
    system, user = build_prompt(ev, "rules say x", {"generic.collect_snapshot"}, "tr")
    boundary = system.split("<<<", 1)[1].split(" ", 1)[0]
    assert boundary.startswith("UNTRUSTED_") and f"<<<{boundary}" in user and "Turkish" in system
    assert "generic.collect_snapshot" in system and "Hunter22" not in user
    # injected text sits strictly inside the fence
    inside = user.split(f"<<<{boundary}", 1)[1].split(f"{boundary}>>>", 1)[0]
    assert "IGNORE ALL PREVIOUS INSTRUCTIONS" in inside


def test_parse_drops_unknown_tools_and_is_never_definitive():
    d = parse_diagnosis(GOOD.replace('"manual": true', '"manual": true, "is_definitive": true'), "e1", "fake:m1", {"generic.collect_snapshot"})
    assert d.is_definitive is False
    assert all(r.tool_id is None for r in d.recommendations)
    assert any("unknown tool" in w for w in d.warnings) and any("command-like" in w for w in d.warnings)


@pytest.mark.parametrize("bad", ["", "no json here", "[1,2,3]", '{"hypotheses": []}'])
def test_parse_rejects_garbage(bad):
    with pytest.raises(ValueError):
        parse_diagnosis(bad, "e1", "x", set())


def test_parse_extracts_json_from_chatter_and_normalises_confidence():
    d = parse_diagnosis('Sure! {"summary":"s","hypotheses":[{"cause":"c","confidence":"CERTAIN"}]} bye', "e1", "x", set())
    assert d.hypotheses[0].confidence.value == "low"


def router(local=None, cloud=None, prices=None, usage=None):
    return HybridRouter(local, cloud, prices or PriceTable(), usage or MemUsage(), lambda: {"generic.collect_snapshot"})


def test_rules_only_when_no_ai():
    r = router().analyze(events(), TenantAIPolicy("t1"), allow_cloud=False, lang="tr")
    assert r.mode == "rules" and all(d.produced_by == "rules" for d in r.diagnoses)
    assert any("kural tabanlı" in n for n in r.notices)


def test_local_ai_used_and_cached():
    local, usage = FakeProvider("ollama"), MemUsage()
    rt = router(local=local, usage=usage)
    evs = events()
    r1 = rt.analyze(evs, TenantAIPolicy("t1"), False, "de")
    assert "local" in r1.mode and any(d.produced_by == "ollama:m1" for d in r1.diagnoses)
    n = local.calls
    r2 = rt.analyze(evs, TenantAIPolicy("t1"), False, "de")
    assert local.calls == n and "cache" in r2.mode  # repeated errors cost nothing
    assert all(c.estimated_cost == 0.0 for c in usage.calls)  # local is free


def test_local_failure_falls_back_to_rules():
    r = router(local=FakeProvider(fail=True)).analyze(events(), TenantAIPolicy("t1"), False, "en")
    assert all(d.produced_by == "rules" for d in r.diagnoses) and any("fell back" in n for n in r.notices)


def test_cloud_requires_tenant_permission_consent_and_budget():
    cloud = FakeProvider("openai", cloud=True)
    prices = PriceTable({"openai:m1": Price(1.0, 4.0)})
    evs = events()
    # no operator consent
    router(cloud=cloud, prices=prices).analyze(evs, TenantAIPolicy("t1", True, 1, 10), allow_cloud=False, lang="en")
    assert cloud.calls == 0
    # tenant not allowed
    r = router(cloud=cloud, prices=prices).analyze(evs, TenantAIPolicy("t1", False, 1, 10), allow_cloud=True, lang="en")
    assert cloud.calls == 0 and any("not permitted" in n for n in r.notices)
    # budget zero
    r = router(cloud=cloud, prices=prices).analyze(evs, TenantAIPolicy("t1", True, 0, 0), allow_cloud=True, lang="en")
    assert cloud.calls == 0 and any("budget" in n for n in r.notices)
    # unknown price => no cloud call
    router(cloud=cloud).analyze(evs, TenantAIPolicy("t1", True, 1, 10), allow_cloud=True, lang="en")
    assert cloud.calls == 0
    # all conditions met
    usage = MemUsage()
    r = router(cloud=cloud, prices=prices, usage=usage).analyze(evs, TenantAIPolicy("t1", True, 1, 10), allow_cloud=True, lang="en")
    assert cloud.calls > 0 and "cloud" in r.mode
    assert usage.calls[0].estimated_cost == pytest.approx(1000 / 1e6 * 1 + 200 / 1e6 * 4)


def test_ollama_provider_protocol():
    seen = {}

    def handler(req: httpx.Request):
        if req.url.path == "/api/tags":
            return httpx.Response(200, json={"models": [{"name": "qwen2.5:7b-instruct"}]})
        seen.update(json.loads(req.content))
        return httpx.Response(200, json={"message": {"content": GOOD}, "prompt_eval_count": 321, "eval_count": 55})

    p = OllamaProvider("http://127.0.0.1:11434", transport=httpx.MockTransport(handler))
    assert p.available()
    res = p.complete("sys", "user")
    assert res.input_tokens == 321 and res.output_tokens == 55 and seen["format"] == "json" and seen["stream"] is False
    down = OllamaProvider(transport=httpx.MockTransport(lambda r: (_ for _ in ()).throw(httpx.ConnectError("x"))))
    assert not down.available()
    with pytest.raises(ProviderError):
        down.complete("s", "u")


def test_openai_provider_protocol_and_key_handling():
    def handler(req):
        assert req.headers["authorization"] == "Bearer sk-test"
        return httpx.Response(200, json={"choices": [{"message": {"content": GOOD}}], "usage": {"prompt_tokens": 10, "completion_tokens": 3}})

    p = OpenAICompatibleProvider("sk-test", "gpt-x", transport=httpx.MockTransport(handler))
    assert p.complete("s", "u").output_tokens == 3
    with pytest.raises(ValueError):
        OpenAICompatibleProvider("", "gpt-x")
    bad = OpenAICompatibleProvider("k", "m", transport=httpx.MockTransport(lambda r: httpx.Response(500)))
    with pytest.raises(ProviderError):
        bad.complete("s", "u")
