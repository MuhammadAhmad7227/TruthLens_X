"""Case-wide real-time job events for M7."""
from __future__ import annotations

import asyncio
from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sqlalchemy import select

from app.api.v1.job_schemas import JobResponse
from app.core.config import get_settings
from app.core.errors import TruthLensError
from app.db.session import get_session_factory
from app.models.analysis import AnalysisJob
from app.services.auth import authenticate_access_token
from app.services.authorization import authorize_case_access

router = APIRouter(prefix="/cases/{case_id}/jobs", tags=["jobs"])


@router.websocket("/ws")
async def case_job_events(websocket: WebSocket, case_id: UUID) -> None:
    token = websocket.headers.get("authorization", "")
    if not token.lower().startswith("bearer "):
        await websocket.close(code=1008)
        return

    session = get_session_factory()()
    try:
        principal = authenticate_access_token(
            session, get_settings(), token[7:].strip()
        )
        authorize_case_access(
            session,
            user=principal.user,
            case_id=case_id,
            capability="view_case",
        )
    except TruthLensError:
        session.close()
        await websocket.close(code=1008)
        return
    finally:
        if not session.is_active:
            session.close()
    session.close()

    await websocket.accept()
    last_seen: dict[UUID, datetime | None] = {}
    try:
        while True:
            poll = get_session_factory()()
            try:
                jobs = list(
                    poll.scalars(
                        select(AnalysisJob)
                        .where(AnalysisJob.case_id == case_id)
                        .order_by(AnalysisJob.queued_at.desc())
                        .limit(100)
                    ).all()
                )
                for job in jobs:
                    marker = job.updated_at
                    if job.id not in last_seen or marker != last_seen[job.id]:
                        await websocket.send_json(
                            {
                                "event": "job",
                                "job": JobResponse.model_validate(job).model_dump(
                                    mode="json"
                                ),
                            }
                        )
                        last_seen[job.id] = marker
            finally:
                poll.close()
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        return
    finally:
        last_seen.clear()
