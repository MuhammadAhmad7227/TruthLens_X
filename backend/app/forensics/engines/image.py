"""M9 image forensic adapters with optional CV dependencies."""

from __future__ import annotations

import hashlib
import math
from typing import Any

MAX_PARAMETER = 100
DEFAULT_QUALITY = 90
DEFAULT_SCALE = 10


def byte_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def perceptual_digest(data: bytes) -> str:
    return hashlib.sha256(b"phash-fallback:" + data).hexdigest()[:16]


def ela_parameters(*, quality: int = DEFAULT_QUALITY, scale: int = DEFAULT_SCALE) -> dict[str, int]:
    if not 1 <= quality <= MAX_PARAMETER or not 1 <= scale <= MAX_PARAMETER:
        raise ValueError(f"quality and scale must be 1..{MAX_PARAMETER}")
    return {"quality": quality, "scale": scale}


def analyse_bytes(data: bytes) -> dict[str, Any]:
    return {
        "entropy": byte_entropy(data),
        "phash_fallback": perceptual_digest(data),
        "requires_human_verification": True,
    }
