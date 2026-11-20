"""M14 advisory indicators. Never returns a binary authenticity verdict."""

from __future__ import annotations

import math
from collections.abc import Iterable


def spectral_peak_score(values: Iterable[float]) -> float:
    xs = list(values)
    if not xs:
        return 0.0
    mean = sum(xs) / len(xs)
    variance = sum((x - mean) ** 2 for x in xs) / len(xs)
    return min(100.0, math.sqrt(variance) * 10)


def advisory(indicators: dict[str, float]) -> dict[str, object]:
    values = [max(0.0, min(100.0, v)) for v in indicators.values()]
    score = sum(values) / len(values) if values else 0.0
    spread = (max(values) - min(values)) if values else 0.0
    margin = min(25.0, spread / 2)
    return {
        "advisory_score": score,
        "confidence_interval": [max(0, score - margin), min(100, score + margin)],
        "indicators": indicators,
        "disclaimer": "Advisory indicators do not prove that media is synthetic or authentic.",
        "requires_human_verification": True,
    }
