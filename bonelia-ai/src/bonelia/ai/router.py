"""Hybrid AI router (Master prompt §4).

1. Classic rules always run first (offline, free).
2. Local AI is used when available and the event warrants it.
3. Cloud AI only with tenant permission + operator consent + remaining budget.
4. Results are cached per fingerprint to avoid paying twice for a repeating error.
5. Any provider failure falls back to the rule diagnosis — the platform never
   blocks on AI.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Callable, Protocol

from ..contracts import Confidence, Diagnosis, DiagnosticEvent, Severity, Triage
from ..diagnostics.engine import diagnose_with_rules
from .costs import PriceTable
from .prompting import build_prompt, parse_diagnosis
from .providers import Provider, ProviderError

log = logging.getLogger("bonelia.ai")


@dataclass
class TenantAIPolicy:
    tenant_id: str
    cloud_allowed: bool = False
    daily_budget: float = 0.0
    monthly_budget: float = 0.0


@dataclass
class AICallRecord:
    tenant_id: str
    provider: str
    model: str
    input_tokens: int
    output_tokens: int
    estimated_cost: float | None
    latency_ms: int
    category: str
    ok: bool


class UsageStore(Protocol):
    def record_ai_call(self, rec: AICallRecord) -> None: ...

    def ai_spend(self, tenant_id: str, period: str) -> float: ...  # period: "day" | "month"

    def cached_diagnosis(self, tenant_id: str, fingerprint: str) -> Diagnosis | None: ...

    def cache_diagnosis(self, tenant_id: str, fingerprint: str, diagnosis: Diagnosis) -> None: ...


@dataclass
class RouterResult:
    diagnoses: list[Diagnosis]
    mode: str
    notices: list[str] = field(default_factory=list)


_NOTICE = {
    "no_ai": {"tr": "Merkezi AI modeli kullanılamıyor — yalnızca kural tabanlı teşhis gösteriliyor.",
              "de": "Zentrales KI-Modell nicht verfügbar — nur regelbasierte Diagnose.",
              "en": "Central AI model unavailable — showing rule-based diagnosis only."},
    "ai_failed": {"tr": "AI yanıtı alınamadı veya geçersizdi; kural tabanlı teşhise dönüldü.",
                  "de": "KI-Antwort fehlgeschlagen oder ungültig; Rückfall auf Regeln.",
                  "en": "AI response failed or was invalid; fell back to rules."},
    "budget": {"tr": "Bulut AI bütçe sınırına ulaşıldı veya fiyat bilinmiyor; bulut kullanılmadı.",
               "de": "Cloud-KI-Budget erreicht oder Preis unbekannt; Cloud nicht genutzt.",
               "en": "Cloud AI budget reached or price unknown; cloud not used."},
    "cloud_denied": {"tr": "Bulut AI bu müşteri için izinli değil.", "de": "Cloud-KI für diesen Kunden nicht freigegeben.",
                     "en": "Cloud AI is not permitted for this customer."},
}


class HybridRouter:
    def __init__(self, local: Provider | None, cloud: Provider | None, prices: PriceTable, usage: UsageStore,
                 allowed_tools: Callable[[], set[str]], max_ai_events: int = 5,
                 history: Callable[[DiagnosticEvent], list[str]] | None = None,
                 brain: Callable[[], tuple[Provider, float] | None] | None = None):
        self.local = local
        self.cloud = cloud
        self.prices = prices
        self.usage = usage
        self.allowed_tools = allowed_tools
        self.max_ai_events = max_ai_events
        self.history = history or (lambda e: [])
        self._local_ok: bool | None = None
        # The "brain" (07.11.2026): Claude for important problems, set up in the panel -> (provider, monthly limit)
        self.brain = brain or (lambda: None)

    def status(self) -> dict:
        return {
            "local": {"provider": self.local.name, "model": self.local.model, "available": self.local_available()} if self.local else None,
            "cloud": {"provider": self.cloud.name, "model": self.cloud.model} if self.cloud else None,
        }

    def local_available(self, refresh: bool = False) -> bool:
        if self.local is None:
            return False
        if self._local_ok is None or refresh:
            self._local_ok = self.local.available()
        return self._local_ok

    @staticmethod
    def _needs_ai(event: DiagnosticEvent, rules: Diagnosis) -> bool:
        if event.triage == Triage.harmless:
            return False  # routine noise: never spend AI time on it
        if event.severity in (Severity.critical, Severity.error):
            return True
        return all(h.confidence == Confidence.low for h in rules.hypotheses)

    def _budget_ok(self, policy: TenantAIPolicy, provider: Provider, est_tokens: int) -> bool:
        est = self.prices.estimate(provider.name, provider.model, est_tokens, 900, provider.is_cloud)
        if est is None:
            return False
        day = self.usage.ai_spend(policy.tenant_id, "day")
        month = self.usage.ai_spend(policy.tenant_id, "month")
        return day + est <= policy.daily_budget and month + est <= policy.monthly_budget

    def _brain_budget_ok(self, provider: Provider, limit: float) -> bool:
        """One monthly limit over all customers; a call is only made when even a long answer stays inside it."""
        est = self.prices.estimate(provider.name, provider.model, 6000, 6000, provider.is_cloud)
        spend_all = getattr(self.usage, "ai_spend_all", None)
        if est is None or spend_all is None:
            return False
        return spend_all("month") + est <= limit

    @staticmethod
    def _important(event: DiagnosticEvent) -> bool:
        return event.triage == Triage.important or event.severity == Severity.critical

    def _ask(self, provider: Provider, event: DiagnosticEvent, rules: Diagnosis, lang: str, tenant_id: str) -> Diagnosis:
        tools = self.allowed_tools()
        system, user = build_prompt(event, rules.summary, tools, lang, self.history(event))
        ok = False
        res = None
        try:
            res = provider.complete(system, user)
            diag = parse_diagnosis(res.text, event.event_id, f"{provider.name}:{provider.model}", tools)
            ok = True
            # keep rule warnings (e.g. injection flags) visible next to AI output
            diag.warnings = list(dict.fromkeys(rules.warnings + diag.warnings))
            return diag
        finally:
            self.usage.record_ai_call(AICallRecord(
                tenant_id=tenant_id, provider=provider.name, model=provider.model,
                input_tokens=res.input_tokens if res else 0, output_tokens=res.output_tokens if res else 0,
                estimated_cost=self.prices.estimate(provider.name, provider.model, res.input_tokens if res else 0,
                                                    res.output_tokens if res else 0, provider.is_cloud),
                latency_ms=res.latency_ms if res else 0, category=event.category.value, ok=ok))

    def analyze(self, events: list[DiagnosticEvent], policy: TenantAIPolicy, allow_cloud: bool, lang: str = "tr") -> RouterResult:
        notices: list[str] = []
        out: list[Diagnosis] = []
        modes: set[str] = set()
        local_ok = self.local_available()
        ai_budget = self.max_ai_events
        try:
            brain = self.brain()
        except Exception as exc:  # a broken brain setting must never stop the analysis
            log.warning("brain unavailable: %s", exc)
            brain = None
        for event in events:
            rules = diagnose_with_rules(event, lang)
            if not self._needs_ai(event, rules) or ai_budget <= 0:
                out.append(rules)
                modes.add("rules")
                continue
            cached = self.usage.cached_diagnosis(policy.tenant_id, event.fingerprint)
            if cached is not None:
                cached = cached.model_copy(update={"event_id": event.event_id})
                out.append(cached)
                modes.add("cache")
                continue
            diag: Diagnosis | None = None
            ai_budget -= 1  # count attempts, not successes: failed calls also cost time
            if brain is not None and self._important(event):
                if not policy.cloud_allowed:
                    notices.append(_NOTICE["cloud_denied"][lang])
                elif not self._brain_budget_ok(*brain):
                    notices.append(_NOTICE["budget"][lang])
                else:
                    try:
                        diag = self._ask(brain[0], event, rules, lang, policy.tenant_id)
                        modes.add("brain")
                    except (ProviderError, ValueError) as exc:
                        log.warning("brain failed: %s", exc)
                        notices.append(_NOTICE["ai_failed"][lang])
            if diag is None and local_ok and self.local is not None:
                try:
                    diag = self._ask(self.local, event, rules, lang, policy.tenant_id)
                    modes.add("local")
                except (ProviderError, ValueError) as exc:
                    log.warning("local AI failed: %s", exc)
                    notices.append(_NOTICE["ai_failed"][lang])
            weak = diag is None or all(h.confidence == Confidence.low for h in diag.hypotheses)
            if weak and allow_cloud and self.cloud is not None:
                if not policy.cloud_allowed:
                    notices.append(_NOTICE["cloud_denied"][lang])
                elif not self._budget_ok(policy, self.cloud, 3000):
                    notices.append(_NOTICE["budget"][lang])
                else:
                    try:
                        diag = self._ask(self.cloud, event, rules, lang, policy.tenant_id)
                        modes.add("cloud")
                    except (ProviderError, ValueError) as exc:
                        log.warning("cloud AI failed: %s", exc)
                        notices.append(_NOTICE["ai_failed"][lang])
            if diag is None:
                out.append(rules)
                modes.add("rules")
            else:
                self.usage.cache_diagnosis(policy.tenant_id, event.fingerprint, diag)
                out.append(diag)
        if not local_ok and not (allow_cloud and self.cloud is not None and policy.cloud_allowed):
            notices.insert(0, _NOTICE["no_ai"][lang])
        mode = "+".join(sorted(modes)) or "rules"
        return RouterResult(diagnoses=out, mode=mode, notices=list(dict.fromkeys(notices)))
