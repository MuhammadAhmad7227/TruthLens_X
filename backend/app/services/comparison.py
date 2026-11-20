"""M15 case-safe comparison primitives."""

from __future__ import annotations

import hashlib
import math


def hamming_hex(a: str, b: str) -> int:
    if len(a) != len(b):
        raise ValueError("Hash lengths differ")
    return sum((int(x, 16) ^ int(y, 16)).bit_count() for x, y in zip(a, b))


def band_for_score(score: float, method: str = "exact_hash") -> str:
    if method == "exact_hash":
        return "identical" if score == 0 else "unrelated"
    if score >= 0.98:
        return "very_high"
    if score >= 0.90:
        return "high"
    if score >= 0.75:
        return "moderate"
    if score >= 0.50:
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
