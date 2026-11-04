"""AI usage and cost accounting.

Prices are configuration, not truth: they MUST be checked against the provider's
current price list (they change). Unknown models are priced as `None` and the
router treats an unknown price as "budget cannot be guaranteed" for cloud calls.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Price:
    input_per_million: float
    output_per_million: float
    currency: str = "EUR"


class PriceTable:
    def __init__(self, prices: dict[str, Price] | None = None):
        self._prices = dict(prices or {})

    def set(self, model_key: str, price: Price) -> None:
        self._prices[model_key] = price

    def estimate(self, provider: str, model: str, input_tokens: int, output_tokens: int, is_cloud: bool) -> float | None:
        if not is_cloud:
            return 0.0  # local inference: no per-call fee (electricity/hardware not modelled)
        price = self._prices.get(f"{provider}:{model}")
        if price is None:
            return None
        return round(input_tokens / 1e6 * price.input_per_million + output_tokens / 1e6 * price.output_per_million, 6)

    @classmethod
    def from_config(cls, cfg: dict) -> "PriceTable":
        prices = {}
        for key, val in (cfg or {}).items():
            prices[key] = Price(float(val["input_per_million"]), float(val["output_per_million"]), val.get("currency", "EUR"))
        return cls(prices)
