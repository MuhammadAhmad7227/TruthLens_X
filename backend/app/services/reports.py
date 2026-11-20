"""Deterministic report manifest and PDF-ready content builder."""

from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_manifest(manifest: dict[str, Any]) -> str:
    return json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def manifest_hash(manifest: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_manifest(manifest).encode()).hexdigest()


def build_report_text(
    title: str, classification: str, sections: list[dict[str, Any]], watermark: str = "DRAFT"
) -> str:
    parts = [classification, title, watermark, ""]
    for section in sections:
        parts.extend([str(section.get("heading", "Section")), str(section.get("body", "")), ""])
    return "\n".join(parts)
