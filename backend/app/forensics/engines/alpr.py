"""M13 ALPR validation with deployment-configured formats."""
from __future__ import annotations
import re
from typing import Any

def validate_plate(value:str,formats:list[dict[str,Any]])->dict[str,Any]:
    candidates=[]
    for fmt in formats:
        if not fmt.get("active",True): continue
        if re.fullmatch(str(fmt["regex"]),value):
            candidates.append(fmt)
    return {"value":value,"format_matched":bool(candidates),"jurisdiction":candidates[0]["jurisdiction"] if candidates else None,"status":"resolved" if candidates else "unmatched-format"}
