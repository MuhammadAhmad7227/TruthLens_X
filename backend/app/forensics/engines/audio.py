"""M11 audio adapters: ffprobe/Whisper are optional and versioned."""

from __future__ import annotations

import json
import shutil
import subprocess  # nosec B404
from typing import Any, cast

try:
    from faster_whisper import WhisperModel
except ImportError:  # pragma: no cover - optional dependency
    WhisperModel = None  # type: ignore[assignment,misc]


def ffprobe(path: str) -> dict[str, Any]:
    binary = shutil.which("ffprobe")
    if binary is None:
        return {"error_class": "DEPENDENCY_UNAVAILABLE", "detail": "ffprobe not installed"}
    completed = subprocess.run(  # nosec B603, S603
        [binary, "-v", "error", "-show_format", "-show_streams", "-of", "json", path],
        capture_output=True,
        text=True,
        check=False,
        shell=False,
    )  # nosec B603, B607
    if completed.returncode != 0:
        return {"error_class": "DECODE_FAILED", "detail": "ffprobe failed"}
    return cast(dict[str, Any], json.loads(completed.stdout))


def asr(path: str, model_name: str) -> dict[str, Any]:
    if WhisperModel is None:
        return {"error_class": "MODEL_UNAVAILABLE", "transcript": []}
    model = WhisperModel(model_name, device="cpu", compute_type="int8")
    segments, info = model.transcribe(path, word_timestamps=True)
    rows = []
    for segment in segments:
        rows.append(
            {
                "start_ms": round(segment.start * 1000),
                "end_ms": round(segment.end * 1000),
                "text": segment.text,
                "words": [w._asdict() for w in (segment.words or [])],
            }
        )
    return {
        "language": info.language,
        "language_probability": info.language_probability,
        "segments": rows,
        "model": model_name,
    }
