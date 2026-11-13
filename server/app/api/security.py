from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_admin
from app.core.db import get_db
from app.models.security import BlockedIP, Command, SecurityEvent
from app.schemas.security import BlockedIPOut, SecurityEventOut

router = APIRouter(prefix="/api/v1", tags=["security"])


@router.get("/security-events", response_model=list[SecurityEventOut])
async def list_security_events(
    status: str | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(SecurityEvent).order_by(SecurityEvent.created_at.desc()).limit(500)
    if status:
        stmt = stmt.where(SecurityEvent.status == status)
    result = await db.execute(stmt)
    return [SecurityEventOut.model_validate(e) for e in result.scalars().all()]


@router.post("/security-events/{event_id}/approve", dependencies=[Depends(require_admin)])
async def approve_security_event(event_id: str, db: AsyncSession = Depends(get_db)):
    event = (
        await db.execute(select(SecurityEvent).where(SecurityEvent.id == event_id))
    ).scalar_one_or_none()
    if event is None:
        raise HTTPException(status_code=404, detail="Evento no encontrado")
    if not event.suggested_action:
        raise HTTPException(status_code=400, detail="Este evento no tiene una accion sugerida")

    if event.suggested_action == "block_ip":
        payload = {"ip": event.source_ip}
    elif event.suggested_action == "kill_process":
        payload = {"pid": event.detail.get("pid"), "cmdline": event.detail.get("cmdline")}
    else:
        raise HTTPException(status_code=400, detail="Accion sugerida desconocida")

    command = Command(
        host_id=event.host_id,
        security_event_id=event.id,
        action=event.suggested_action,
        payload=payload,
    )
    db.add(command)
    event.status = "approved"
    await db.commit()
    return {"status": "ok", "command_id": str(command.id)}


@router.post("/security-events/{event_id}/dismiss", dependencies=[Depends(require_admin)])
async def dismiss_security_event(event_id: str, db: AsyncSession = Depends(get_db)):
    event = (
        await db.execute(select(SecurityEvent).where(SecurityEvent.id == event_id))
    ).scalar_one_or_none()
    if event is None:
        raise HTTPException(status_code=404, detail="Evento no encontrado")
    event.status = "dismissed"
    await db.commit()
    return {"status": "ok"}


@router.get("/blocked-ips", response_model=list[BlockedIPOut])
async def list_blocked_ips(db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(BlockedIP).where(BlockedIP.unblocked_at.is_(None)).order_by(BlockedIP.blocked_at.desc())
    )
    return [BlockedIPOut.model_validate(b) for b in result.scalars().all()]


@router.post("/blocked-ips/{blocked_id}/unblock", dependencies=[Depends(require_admin)])
async def unblock_ip(blocked_id: str, db: AsyncSession = Depends(get_db)):
    blocked = (await db.execute(select(BlockedIP).where(BlockedIP.id == blocked_id))).scalar_one_or_none()
    if blocked is None:
        raise HTTPException(status_code=404, detail="No encontrado")

    command = Command(host_id=blocked.host_id, action="unblock_ip", payload={"ip": blocked.ip})
    db.add(command)
    blocked.unblocked_at = datetime.now(timezone.utc)
    await db.commit()
    return {"status": "ok", "command_id": str(command.id)}
