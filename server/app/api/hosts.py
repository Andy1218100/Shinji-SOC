import secrets

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_admin
from app.core.db import get_db
from app.models.alert import Alert, AlertRule
from app.models.host import Host
from app.models.metric import Metric
from app.models.security import AuthAttempt, BlockedIP, Command, IngestedRequest, SecurityEvent
from app.models.system_report import SystemReport
from app.models.user import User
from app.models.vulnerability import InstalledPackage, VulnerabilityFinding
from app.schemas.host import GrantLogAccessRequest, HostCreate, HostCreated, HostDeleteRequest, HostOut
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
    await db.execute(delete(AuthAttempt).where(AuthAttempt.host_id == host.id))
    await db.execute(delete(InstalledPackage).where(InstalledPackage.host_id == host.id))
    await db.execute(delete(VulnerabilityFinding).where(VulnerabilityFinding.host_id == host.id))
    await db.execute(delete(SystemReport).where(SystemReport.host_id == host.id))
    await db.execute(delete(Alert).where(Alert.host_id == host.id))
    await db.execute(delete(AlertRule).where(AlertRule.host_id == host.id))
    await db.execute(delete(Metric).where(Metric.host_id == host.id))
    await db.delete(host)
    await db.commit()
    return {"status": "ok"}


@router.post("/{host_id}/grant-log-access")
async def grant_log_access(
    host_id: str,
    payload: GrantLogAccessRequest,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Encola en el agente un otorgamiento de permiso de lectura (ACL,
    nunca cambia duenos ni permisos existentes) sobre una carpeta/archivo
    que el propio descubrimiento del host marco como no accesible. Pide
    MFA como paso extra: es una escalada de privilegios real del agente
    sobre el filesystem del host, aunque acotada (ver
    agent/grant_log_access.sh) -- nunca sobre /root, y solo sobre lo que
    el ultimo informe de este host efectivamente reporto como bloqueado,
    no cualquier ruta arbitraria."""
    host = (await db.execute(select(Host).where(Host.id == host_id))).scalar_one_or_none()
    if host is None:
        raise HTTPException(status_code=404, detail="Host no encontrado")

    if not auth.verify_totp(admin.mfa_secret, payload.mfa_code):
        raise HTTPException(status_code=401, detail="Codigo MFA invalido")

    report = (
        await db.execute(select(SystemReport).where(SystemReport.host_id == host.id))
    ).scalar_one_or_none()
    raw = report.raw if report else {}
    known_paths = set(raw.get("unreadable_log_paths") or []) | set(raw.get("denied_log_dirs") or [])
    if payload.path not in known_paths:
        raise HTTPException(
            status_code=400,
            detail="Esa ruta no figura en el ultimo informe de este host como bloqueada",
        )

    command = Command(host_id=host.id, action="grant_log_access", payload={"path": payload.path})
    db.add(command)
    await db.commit()
    await db.refresh(command)
    return {"status": "ok", "command_id": str(command.id)}


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
        "ai_source": report.ai_source,
        "audited_at": report.audited_at,
        "audit_note": report.audit_note,
        "generated_at": report.generated_at,
    }
