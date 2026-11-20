"""M12 streaming media primitives."""

from __future__ import annotations

import json
import shutil
import subprocess  # nosec B404
from typing import Any, cast


def probe(path: str) -> dict[str, Any]:
    binary = shutil.which("ffprobe")
    if binary is None:
        return {"error_class": "DEPENDENCY_UNAVAILABLE", "detail": "ffprobe not installed"}
    p = subprocess.run(  # nosec B603, S603
        [binary, "-v", "error", "-of", "json", "-show_format", "-show_streams", path],
        capture_output=True,
        text=True,
        check=False,
        shell=False,
    )  # nosec B603, B607
    if p.returncode != 0:
        return {"error_class": "DECODE_FAILED"}
    return cast(dict[str, Any], json.loads(p.stdout))


def frame_plan(duration_seconds: float, interval: float) -> list[float]:
    if duration_seconds < 0 or interval <= 0:
        raise ValueError("invalid duration or interval")
    return [round(i * interval, 6) for i in range(int(duration_seconds // interval) + 1)]
