import asyncio

from fastapi import APIRouter, Depends
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_host
from app.core.db import get_db
from app.models.host import Host
from app.models.vulnerability import InstalledPackage
from app.schemas.logs import (AuthEventBatchIn, ConnectionsIn, InventoryIn, LogBatchIn, ProcessEventBatchIn,
                              SystemReportIn, WafBatchIn)
from app.services import conn_watch, ids, process_anomaly, system_report, vuln_scan

router = APIRouter(prefix="/api/v1", tags=["security-ingest"])


@router.post("/logs/ingest", status_code=201)
async def ingest_logs(
    payload: LogBatchIn,
    host: Host = Depends(get_current_host),
    db: AsyncSession = Depends(get_db),
):
    await ids.process_log_entries(db, host, payload.entries)
    return {"status": "ok", "received": len(payload.entries)}


@router.post("/auth-events/ingest", status_code=201)
async def ingest_auth_events(
    payload: AuthEventBatchIn,
    host: Host = Depends(get_current_host),
    db: AsyncSession = Depends(get_db),
):
    await ids.process_auth_events(db, host, payload.entries)
    return {"status": "ok", "received": len(payload.entries)}


@router.post("/connections/ingest", status_code=201)
async def ingest_connections(
    payload: ConnectionsIn,
    host: Host = Depends(get_current_host),
    db: AsyncSession = Depends(get_db),
):
    await conn_watch.process_connections(db, host, payload)
    return {"status": "ok", "outbound": len(payload.outbound),
            "listeners": None if payload.listeners is None else len(payload.listeners)}


@router.post("/waf/ingest", status_code=201)
async def ingest_waf(
    payload: WafBatchIn,
    host: Host = Depends(get_current_host),
    db: AsyncSession = Depends(get_db),
):
    await ids.process_waf_entries(db, host, payload)
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
    # Con multiarch (amd64 + i386, comun en hosts con servidores de juegos)
    # dpkg lista el mismo paquete una vez por arquitectura; la tabla es
    # unica por (host, nombre). Agentes viejos todavia mandan duplicados.
    unique = {pkg.name: pkg for pkg in payload.packages}
    for pkg in unique.values():
        db.add(
            InstalledPackage(
                host_id=host.id,
                name=pkg.name,
                version=pkg.version,
                source_name=pkg.source_name,
                source_version=pkg.source_version,
            )
        )
    if payload.debian_release:
        host.debian_release = payload.debian_release
    await db.commit()
    # Escanear con este inventario ya, sin esperar al ciclo diario: llega por
    # el envio diario del agente, al reinstalarlo, o por "Escanear ahora".
    asyncio.create_task(vuln_scan.scan_host_by_id(host.id))
    return {"status": "ok", "received": len(unique)}


@router.post("/system-report/ingest", status_code=201)
async def ingest_system_report(
    payload: SystemReportIn,
    host: Host = Depends(get_current_host),
    db: AsyncSession = Depends(get_db),
):
    """Lo que el agente descubre del sistema al arrancar (y despues una vez
    al dia): sistema operativo, hardware, servicios, puertos, y que logs/
    cuentas de servicio detecto para vigilar. Actualiza el perfil del host
    y dispara el informe de IA."""
    if payload.os_name:
        host.os = payload.os_name
    if payload.os_version_id:
        host.debian_release = payload.os_version_id
    await db.commit()

    await system_report.save_and_summarize(db, host, payload)
    return {"status": "ok"}
