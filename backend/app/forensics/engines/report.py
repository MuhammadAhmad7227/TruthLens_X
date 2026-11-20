"""M18 deterministic report renderer."""
from __future__ import annotations
from io import BytesIO
from typing import Any

def render_pdf(title:str,sections:list[dict[str,Any]])->bytes:
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas
    except ImportError:
        raise RuntimeError("MODEL_UNAVAILABLE: reportlab is not installed")
    out=BytesIO(); pdf=canvas.Canvas(out,pagesize=A4)
    width,height=A4; y=height-60
    pdf.setTitle(title); pdf.drawString(50,y,title); y-=30
    for section in sections:
        if y<70: pdf.showPage(); y=height-60
        pdf.drawString(50,y,str(section.get("heading","Section"))); y-=18
        for line in str(section.get("body","")).splitlines():
            if y<50: pdf.showPage(); y=height-60
            pdf.drawString(60,y,line[:110]); y-=14
    pdf.save(); return out.getvalue()
