import secrets

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_admin
from app.core.db import get_db
from app.models.alert import Alert, AlertRule
from app.models.host import Host
from app.models.metric import Metric
from app.models.security import BlockedIP, Command, IngestedRequest, SecurityEvent
from app.models.system_report import SystemReport
from app.models.user import User
from app.models.vulnerability import InstalledPackage, VulnerabilityFinding
from app.schemas.host import HostCreate, HostCreated, HostDeleteRequest, HostOut
from app.services import auth, geoip

router = APIRouter(prefix="/api/v1/hosts", tags=["hosts"])


def _host_out_with_geo(host: Host) -> HostOut:
    out = HostOut.model_validate(host)
    if host.ip_address:
        geo = geoip.lookup(host.ip_address)
        out.geo_lat = geo.lat
        out.geo_lon = geo.lon
    return out


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


@router.get("", response_model=list[HostOut], dependencies=[Depends(get_current_user)])
async def list_hosts(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Host).order_by(Host.name))
    return [_host_out_with_geo(h) for h in result.scalars().all()]


@router.get("/{host_id}", response_model=HostOut, dependencies=[Depends(get_current_user)])
async def get_host(host_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Host).where(Host.id == host_id))
    host = result.scalar_one_or_none()
    if host is None:
        raise HTTPException(status_code=404, detail="Host no encontrado")
    return _host_out_with_geo(host)


@router.delete("/{host_id}")
async def delete_host(
    host_id: str,
    payload: HostDeleteRequest,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Borrado permanente: ademas de admin, pide el codigo MFA del que lo
    hace como paso extra (un host acumula historial real de metricas y
    seguridad -- el borrado accidental no es recuperable)."""
    host = (await db.execute(select(Host).where(Host.id == host_id))).scalar_one_or_none()
    if host is None:
        raise HTTPException(status_code=404, detail="Host no encontrado")

    if not auth.verify_totp(admin.mfa_secret, payload.mfa_code):
        raise HTTPException(status_code=401, detail="Codigo MFA invalido")

    # Orden que respeta las foreign keys: lo que depende de security_events
    # primero, despues el resto de las tablas que dependen de hosts.
    await db.execute(delete(Command).where(Command.host_id == host.id))
    await db.execute(delete(SecurityEvent).where(SecurityEvent.host_id == host.id))
    await db.execute(delete(BlockedIP).where(BlockedIP.host_id == host.id))
    await db.execute(delete(IngestedRequest).where(IngestedRequest.host_id == host.id))
    await db.execute(delete(InstalledPackage).where(InstalledPackage.host_id == host.id))
    await db.execute(delete(VulnerabilityFinding).where(VulnerabilityFinding.host_id == host.id))
    await db.execute(delete(SystemReport).where(SystemReport.host_id == host.id))
    await db.execute(delete(Alert).where(Alert.host_id == host.id))
    await db.execute(delete(AlertRule).where(AlertRule.host_id == host.id))
    await db.execute(delete(Metric).where(Metric.host_id == host.id))
    await db.delete(host)
    await db.commit()
    return {"status": "ok"}


@router.get("/{host_id}/system-report", dependencies=[Depends(get_current_user)])
async def get_system_report(host_id: str, db: AsyncSession = Depends(get_db)):
    report = (
        await db.execute(select(SystemReport).where(SystemReport.host_id == host_id))
    ).scalar_one_or_none()
    if report is None:
        return {"available": False}
    return {
        "available": True,
        "raw": report.raw,
        "ai_summary": report.ai_summary,
        "generated_at": report.generated_at,
    }
