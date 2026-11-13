from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_host
from app.core.db import get_db
from app.models.host import Host
from app.schemas.logs import LogBatchIn, ProcessEventBatchIn
from app.services import ids, process_anomaly

router = APIRouter(prefix="/api/v1", tags=["security-ingest"])


@router.post("/logs/ingest", status_code=201)
async def ingest_logs(
    payload: LogBatchIn,
    host: Host = Depends(get_current_host),
    db: AsyncSession = Depends(get_db),
):
    await ids.process_log_entries(db, host, payload.entries)
    return {"status": "ok", "received": len(payload.entries)}


@router.post("/process-events/ingest", status_code=201)
async def ingest_process_events(
    payload: ProcessEventBatchIn,
    host: Host = Depends(get_current_host),
    db: AsyncSession = Depends(get_db),
):
    await process_anomaly.process_anomalies(db, host, payload.events)
    return {"status": "ok", "received": len(payload.events)}
