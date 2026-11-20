"""M15 case-safe comparison primitives."""

from __future__ import annotations

import hashlib
import math

VERY_HIGH_THRESHOLD = 0.98
HIGH_THRESHOLD = 0.90
MODERATE_THRESHOLD = 0.75
LOW_THRESHOLD = 0.50


def hamming_hex(a: str, b: str) -> int:
    if len(a) != len(b):
        raise ValueError("Hash lengths differ")
    return sum((int(x, 16) ^ int(y, 16)).bit_count() for x, y in zip(a, b, strict=True))


def band_for_score(score: float, method: str = "exact_hash") -> str:
    if method == "exact_hash":
        return "identical" if score == 0 else "unrelated"
    if score >= VERY_HIGH_THRESHOLD:
        return "very_high"
    if score >= HIGH_THRESHOLD:
        return "high"
    if score >= MODERATE_THRESHOLD:
        return "moderate"
    if score >= LOW_THRESHOLD:
        return "low"
    return "unrelated"


def cosine(a: list[float], b: list[float]) -> float:
    if len(a) != len(b) or not a:
        raise ValueError("Vectors must have equal non-zero dimensions")
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    return 0.0 if not na or not nb else dot / (na * nb)


def exact_digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
