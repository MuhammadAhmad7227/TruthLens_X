"""M18 deterministic report renderer."""

from __future__ import annotations

from io import BytesIO
from typing import Any

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas
except ImportError:  # pragma: no cover - optional dependency
    A4 = None  # type: ignore[assignment]
    canvas = None  # type: ignore[assignment,misc]

TOP_MARGIN = 60
BOTTOM_MARGIN = 50
PAGE_BREAK_THRESHOLD = 70
HEADING_GAP = 30
SECTION_GAP = 18
LINE_GAP = 14
TEXT_X = 50
BODY_X = 60
MAX_LINE_LENGTH = 110


def render_pdf(title: str, sections: list[dict[str, Any]]) -> bytes:
    if A4 is None or canvas is None:
        raise RuntimeError("MODEL_UNAVAILABLE: reportlab is not installed")
    out = BytesIO()
    pdf = canvas.Canvas(out, pagesize=A4)
    _, height = A4
    y = height - TOP_MARGIN
    pdf.setTitle(title)
    pdf.drawString(TEXT_X, y, title)
    y -= HEADING_GAP
    for section in sections:
        if y < PAGE_BREAK_THRESHOLD:
            pdf.showPage()
            y = height - TOP_MARGIN
        pdf.drawString(TEXT_X, y, str(section.get("heading", "Section")))
        y -= SECTION_GAP
        for line in str(section.get("body", "")).splitlines():
            if y < BOTTOM_MARGIN:
                pdf.showPage()
                y = height - TOP_MARGIN
            pdf.drawString(BODY_X, y, line[:MAX_LINE_LENGTH])
            y -= LINE_GAP
    pdf.save()
    return out.getvalue()
