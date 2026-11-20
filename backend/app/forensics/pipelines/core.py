"""Shared deterministic pipeline primitives.

Heavy ML libraries are optional. Every pipeline still emits a truthful, versioned result envelope
when an optional engine is unavailable; it never fabricates a forensic conclusion.
"""
from __future__ import annotations

import hashlib
import math
import statistics
from dataclasses import dataclass
from typing import Any, Callable

from app.forensics.contracts.results import ForensicResultContract, Provenance, validate_result

ENGINE_VERSION = "1.0.0"

@dataclass(frozen=True)
class PipelineInput:
    pipeline: str
    source_sha256: str
    data: bytes
    parameters: dict[str, Any]

@dataclass(frozen=True)
class PipelineOutput:
    result: ForensicResultContract
    artifacts: tuple[bytes, ...]

def _digest_stats(data: bytes) -> dict[str, Any]:
    if not data:
        return {"size": 0, "entropy": 0.0, "zero_ratio": 1.0}
    counts = [0] * 256
    for value in data:
        counts[value] += 1
    size = len(data)
    entropy = -sum((n / size) * math.log2(n / size) for n in counts if n)
    zero_ratio = counts[0] / size
    return {"size": size, "entropy": round(entropy, 6), "zero_ratio": round(zero_ratio, 6)}

def _result(inp: PipelineInput, summary: str, indicators: list[dict[str, Any]], limitation: str) -> ForensicResultContract:
    payload = {
        "schema_version": "1.0",
        "pipeline": inp.pipeline,
        "pipeline_version": ENGINE_VERSION,
        "summary": summary,
        "indicators": indicators,
        "provenance": {
            "engine": "truthlens.deterministic",
            "engine_version": ENGINE_VERSION,
            "source_sha256": inp.source_sha256,
            "parameters": inp.parameters,
        },
        "limitations_code": limitation,
        "requires_human_verification": True,
    }
    return validate_result(payload)

def _image(inp: PipelineInput) -> PipelineOutput:
    stats = _digest_stats(inp.data)
    # A deterministic byte-domain ELA proxy. It is intentionally called a proxy rather than
    # JPEG ELA because a byte transform cannot establish image recompression.
    block = int(inp.parameters.get("block_size", 64))
    blocks = [inp.data[i:i + block] for i in range(0, len(inp.data), block)]
    variances = [statistics.pvariance(b) for b in blocks if len(b) > 1]
    score = min(100.0, statistics.mean(variances) / 200.0) if variances else 0.0
    return PipelineOutput(
        _result(inp, "Byte-domain image anomaly screening completed; this is not proof of manipulation.", [
            {"code": "ELA_PROXY", "label": "Recompression/anomaly proxy", "value": round(score, 3), "unit": "score", "confidence": None, "region": None, "interpretation": "Screening signal only; inspect the original image and corroborating evidence."},
            {"code": "BYTE_ENTROPY", "label": "Byte entropy", "value": stats["entropy"], "unit": "bits", "confidence": None, "region": None, "interpretation": "Descriptive property of the supplied bytes."},
        ], "ELA"),
        (),
    )

def _document(inp: PipelineInput) -> PipelineOutput:
    text = inp.data.decode("utf-8", errors="replace")
    markers = {"pdf": text.startswith("%PDF-"), "xml": "<?xml" in text[:512], "zip": inp.data[:2] == b"PK"}
    return PipelineOutput(_result(inp, "Document/container structure screening completed.", [
        {"code": "FORMAT_MARKERS", "label": "Container markers", "value": markers, "unit": "boolean", "confidence": None, "region": None, "interpretation": "Markers describe structure; they do not establish authorship or authenticity."},
        {"code": "TEXT_LENGTH", "label": "Decoded text length", "value": len(text), "unit": "characters", "confidence": None, "region": None, "interpretation": "Best-effort UTF-8 extraction only."},
    ], "DOCUMENT_STRUCTURE"), ())

def _audio(inp: PipelineInput) -> PipelineOutput:
    stats = _digest_stats(inp.data)
    return PipelineOutput(_result(inp, "Audio byte-level screening completed; codec/ASR engines were not invoked by this lightweight path.", [
        {"code": "AUDIO_ENTROPY", "label": "Byte entropy", "value": stats["entropy"], "unit": "bits", "confidence": None, "region": None, "interpretation": "Descriptive only."},
        {"code": "DYNAMIC_PROXY", "label": "Zero-byte ratio", "value": stats["zero_ratio"], "unit": "ratio", "confidence": None, "region": None, "interpretation": "Not a substitute for waveform analysis."},
    ], "AUDIO_SCREENING"), ())

def _video(inp: PipelineInput) -> PipelineOutput:
    size = len(inp.data)
    interval = int(inp.parameters.get("interval_seconds", 1))
    estimated_frames = max(1, size // max(1, int(inp.parameters.get("bytes_per_frame_estimate", 100_000))))
    return PipelineOutput(_result(inp, "Video processing plan created without loading the entire file into memory.", [
        {"code": "ESTIMATED_FRAME_COUNT", "label": "Estimated frame count", "value": estimated_frames, "unit": "frames", "confidence": None, "region": None, "interpretation": "Planning estimate; exact PTS requires ffprobe/frame decoding."},
        {"code": "SAMPLING_INTERVAL", "label": "Requested interval", "value": interval, "unit": "seconds", "confidence": None, "region": None, "interpretation": "Exact keyframe extraction requires a media decoder."},
    ], "VIDEO_SCREENING"), ())

def _detection(inp: PipelineInput) -> PipelineOutput:
    return PipelineOutput(_result(inp, "Detection adapter is ready; no detector weight was executed for this input.", [
        {"code": "DETECTOR_UNAVAILABLE", "label": "Detector execution", "value": False, "unit": "available", "confidence": None, "region": None, "interpretation": "Install and pin an approved detector/model before producing detections."},
    ], "MODEL_UNAVAILABLE"), ())

def _deepfake(inp: PipelineInput) -> PipelineOutput:
    return PipelineOutput(_result(inp, "Deepfake indicator aggregation requires modality-specific frequency, face and temporal features.", [
        {"code": "INSUFFICIENT_MODALITY_FEATURES", "label": "Feature coverage", "value": 0.0, "unit": "ratio", "confidence": None, "region": None, "interpretation": "No authenticity verdict is produced."},
    ], "DEEPFAKE"), ())

def _compare(inp: PipelineInput) -> PipelineOutput:
    digest = hashlib.sha256(inp.data).hexdigest()
    return PipelineOutput(_result(inp, "Exact byte comparison completed.", [
        {"code": "EXACT_SHA256", "label": "SHA-256", "value": digest, "unit": "digest", "confidence": None, "region": None, "interpretation": "Identical hashes mean identical byte sequences under the same SHA-256 algorithm."},
    ], "COMPARISON"), ())

def _generic(inp: PipelineInput) -> PipelineOutput:
    return PipelineOutput(_result(inp, f"Pipeline {inp.pipeline} executed in safe adapter mode.", [
        {"code": "ADAPTER_READY", "label": "Pipeline adapter", "value": True, "unit": "boolean", "confidence": None, "region": None, "interpretation": "This adapter is safe to replace with the approved model implementation without changing the result contract."}
    ], "ENGINE_LIMITATION"), ())

PIPELINES: dict[str, Callable[[PipelineInput], PipelineOutput]] = {
    "image.ela": _image, "image.forensics": _image, "doc.structure": _document,
    "doc.revisions": _document, "audio.screen": _audio, "audio.asr": _audio,
    "video.screen": _video, "video.frames": _video, "video.detect_track": _detection,
    "detection.objects": _detection, "alpr.plate": _detection,
    "deepfake.indicators": _deepfake, "comparison.exact": _compare,
    "comparison.similarity": _compare,
    "image.dqt": _generic, "image.phash": _generic, "image.copy_move": _generic, "image.face_regions": _generic,
    "doc.attachments": _generic, "doc.ocr": _generic, "doc.ooxml": _generic,
    "audio.diarization": _generic, "audio.splice": _generic, "audio.synthetic": _generic,
    "video.shots": _generic, "video.temporal": _generic, "video.audio_extract": _generic,
    "detection.tracks": _generic, "alpr.plate": _detection,
    "deepfake.frequency": _generic, "deepfake.face": _generic, "deepfake.temporal": _generic, "deepfake.audio": _generic,
    "deepfake.indicators": _deepfake, "comparison.phash": _generic, "comparison.feature": _generic,
    "comparison.embedding": _generic, "comparison.metadata": _generic,
    "graph.entities": _generic, "graph.edges": _generic, "timeline.assemble": _generic, "graph.export": _generic,
    "assistant.retrieve": _generic, "assistant.answer": _generic, "assistant.actions": _generic,
    "report.manifest": _generic, "report.generate": _generic, "report.verify": _generic,
}

def run_pipeline(inp: PipelineInput) -> PipelineOutput:
    handler = PIPELINES.get(inp.pipeline)
    if handler is None:
        raise ValueError(f"Unsupported pipeline: {inp.pipeline}")
    return handler(inp)
