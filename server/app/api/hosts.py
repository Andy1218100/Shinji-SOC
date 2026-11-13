import secrets

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_admin
from app.core.db import get_db
from app.models.host import Host
from app.schemas.host import HostCreate, HostCreated, HostOut

router = APIRouter(prefix="/api/v1/hosts", tags=["hosts"])


@router.post("", response_model=HostCreated, dependencies=[Depends(require_admin)])
async def create_host(payload: HostCreate, db: AsyncSession = Depends(get_db)):
    host = Host(
        name=payload.name,
        hostname=payload.hostname,
        ip_address=payload.ip_address,
        os=payload.os,
        api_key=secrets.token_hex(24),
    )
    db.add(host)
    await db.commit()
    await db.refresh(host)
    return HostCreated(
        id=str(host.id),
        name=host.name,
        hostname=host.hostname,
        ip_address=host.ip_address,
        os=host.os,
        last_seen=host.last_seen,
        api_key=host.api_key,
    )


@router.get("", response_model=list[HostOut])
async def list_hosts(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Host).order_by(Host.name))
    return [HostOut.model_validate(h) for h in result.scalars().all()]


@router.get("/{host_id}", response_model=HostOut)
async def get_host(host_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Host).where(Host.id == host_id))
    host = result.scalar_one_or_none()
    if host is None:
        raise HTTPException(status_code=404, detail="Host no encontrado")
    return HostOut.model_validate(host)
