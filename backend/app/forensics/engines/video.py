"""M12 streaming media primitives."""

from __future__ import annotations

import json
import subprocess
from typing import Any


def probe(path: str) -> dict[str, Any]:
    p = subprocess.run(
        ["ffprobe", "-v", "error", "-of", "json", "-show_format", "-show_streams", path],
        capture_output=True,
        text=True,
        check=False,
        shell=False,
    )  # noqa: S603
    if p.returncode != 0:
        return {"error_class": "DECODE_FAILED"}
    return json.loads(p.stdout)


def frame_plan(duration_seconds: float, interval: float) -> list[float]:
    if duration_seconds < 0 or interval <= 0:
        raise ValueError("invalid duration or interval")
    return [round(i * interval, 6) for i in range(int(duration_seconds // interval) + 1)]
