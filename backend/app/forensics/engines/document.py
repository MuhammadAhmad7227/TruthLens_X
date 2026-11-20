"""M10 document adapters using permissive pikepdf when installed."""

from __future__ import annotations

from typing import Any


def inspect_pdf(data: bytes) -> dict[str, Any]:
    if not data.startswith(b"%PDF-"):
        return {"format": "unknown", "pages": None, "engine": "signature-only"}
    try:
        import io

        import pikepdf  # type: ignore[import-not-found]

        with pikepdf.open(io.BytesIO(data)) as pdf:
            return {
                "format": "pdf",
                "pages": len(pdf.pages),
                "metadata": dict(pdf.docinfo),
                "engine": "pikepdf",
            }
    except ImportError:
        return {
            "format": "pdf",
            "pages": None,
            "engine": "signature-only",
            "error_class": "MODEL_UNAVAILABLE",
        }