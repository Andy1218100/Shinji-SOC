from fastapi import APIRouter, Depends
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_host
from app.core.db import get_db
from app.models.host import Host
from app.models.vulnerability import InstalledPackage
from app.schemas.logs import InventoryIn, LogBatchIn, ProcessEventBatchIn
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


@router.post("/inventory/ingest", status_code=201)
async def ingest_inventory(
    payload: InventoryIn,
    host: Host = Depends(get_current_host),
    db: AsyncSession = Depends(get_db),
):
    """Reemplaza el inventario de paquetes del host por el ultimo reporte
    (es una foto completa, no un delta)."""
    await db.execute(delete(InstalledPackage).where(InstalledPackage.host_id == host.id))
    for pkg in payload.packages:
        db.add(InstalledPackage(host_id=host.id, name=pkg.name, version=pkg.version))
    if payload.debian_release:
        host.debian_release = payload.debian_release
    await db.commit()
    return {"status": "ok", "received": len(payload.packages)}
