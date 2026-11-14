"""Motor de deteccion de intrusos para Prox Secure.

Es heuristico (reglas + conteos en ventana deslizante), no un modelo de
machine learning entrenado. "Aprende" en el sentido de que acumula, por
host, los user-agents y rutas sospechosas vistas, no de que entrene pesos.
"""

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.host import Host
from app.models.security import IngestedRequest, SecurityEvent
from app.schemas.logs import LogEntryIn
from app.services import ai, geoip
from app.services.event_bus import security_events_bus

logger = logging.getLogger("ids")

SUSPICIOUS_PATH_MARKERS = (
    "wp-admin", "wp-login", ".env", ".git", "phpmyadmin", "xmlrpc.php",
    "/etc/passwd", "../", "..%2f", "shell.php", "cmd.php", "adminer.php",
    ".sql", "config.php.bak", "/actuator", "/.aws", "/.ssh",
)


def is_suspicious_path(path: str) -> bool:
    lowered = path.lower()
    return any(marker in lowered for marker in SUSPICIOUS_PATH_MARKERS)


async def _open_event(session: AsyncSession, host_id, kind: str, source_ip: str) -> SecurityEvent | None:
    result = await session.execute(
        select(SecurityEvent).where(
            SecurityEvent.host_id == host_id,
            SecurityEvent.kind == kind,
            SecurityEvent.source_ip == source_ip,
            SecurityEvent.status == "open",
        )
    )
    return result.scalar_one_or_none()


async def create_event(
    session: AsyncSession,
    host: Host,
    kind: str,
    source_ip: str,
    detail: dict,
    severity: str = "warning",
    suggested_action: str | None = "block_ip",
) -> SecurityEvent:
    geo = geoip.lookup(source_ip)
    event = SecurityEvent(
        host_id=host.id,
        kind=kind,
        severity=severity,
        source_ip=source_ip,
        detail=detail,
        suggested_action=suggested_action,
        geo_country=geo.country,
        geo_city=geo.city,
        geo_lat=geo.lat,
        geo_lon=geo.lon,
    )
    session.add(event)
    await session.commit()
    await session.refresh(event)
    security_events_bus.publish({"event_id": str(event.id)})

    prompt = (
        f"Se detecto un posible ataque tipo '{kind}' desde la IP {source_ip} contra "
        f"el host '{host.name}'. Evidencia: {detail}. Explica en 2-3 frases que esta "
        "intentando el atacante y si conviene bloquear la IP."
    )
    try:
        event.ai_summary = await ai.ask(prompt)
        await session.commit()
    except Exception:
        logger.exception("No se pudo generar el resumen de IA para el evento de seguridad")

    return event


async def process_log_entries(session: AsyncSession, host: Host, entries: list[LogEntryIn]) -> None:
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(seconds=settings.ids_window_seconds)

    for entry in entries:
        session.add(
            IngestedRequest(
                host_id=host.id,
                ts=entry.ts or now,
                ip=entry.ip,
                method=entry.method,
                path=entry.path,
                status_code=entry.status_code,
                user_agent=entry.user_agent,
            )
        )

        if entry.path and is_suspicious_path(entry.path) and not await _open_event(
            session, host.id, "path_scan", entry.ip
        ):
            await create_event(
                session,
                host,
                "path_scan",
                entry.ip,
                {"path": entry.path, "method": entry.method, "user_agent": entry.user_agent},
            )

    await session.commit()

    ips = {e.ip for e in entries}
    for ip in ips:
        total = (
            await session.execute(
                select(func.count(IngestedRequest.id)).where(
                    IngestedRequest.host_id == host.id,
                    IngestedRequest.ip == ip,
                    IngestedRequest.ts >= window_start,
                )
            )
        ).scalar_one()

        if total >= settings.ids_requests_threshold and not await _open_event(session, host.id, "brute_force", ip):
            await create_event(
                session,
                host,
                "brute_force",
                ip,
                {"requests_in_window": total, "window_seconds": settings.ids_window_seconds},
                severity="critical",
            )
            continue

        not_found = (
            await session.execute(
                select(func.count(IngestedRequest.id)).where(
                    IngestedRequest.host_id == host.id,
                    IngestedRequest.ip == ip,
                    IngestedRequest.ts >= window_start,
                    IngestedRequest.status_code == 404,
                )
            )
        ).scalar_one()

        if not_found >= settings.ids_404_threshold and not await _open_event(session, host.id, "path_scan", ip):
            await create_event(
                session,
                host,
                "path_scan",
                ip,
                {"not_found_in_window": not_found, "window_seconds": settings.ids_window_seconds},
            )
