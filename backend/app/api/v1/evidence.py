"""M5 evidence endpoints."""
from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, File, Form, UploadFile
from sqlalchemy.orm import Session

from app.api.v1.auth_deps import CurrentPrincipal
from app.api.v1.evidence_schemas import EvidenceIntegrityResponse, EvidenceListResponse, EvidenceResponse
from app.core.config import Settings, get_settings
from app.db.session import get_db
from app.services import evidence as evidence_service

router = APIRouter(prefix="/cases/{case_id}/evidence", tags=["evidence"])
