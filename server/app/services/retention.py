"""Retencion de datos: purga diaria de lo que crece sin limite.

- metrics (hypertable): drop_chunks de lo mas viejo que RETENTION_METRICS_DAYS.
  Ademas se comprime (columnstore de TimescaleDB) lo que tiene mas de 7 dias,
  con la politica que crea ensure_metrics_compression().
- ingested_requests y auth_attempts: ventanas cortas para el IDS; se guardan
  RETENTION_REQUESTS_DAYS por si hace falta revisar un incidente.
- security_events cerrados (aprobados o descartados): RETENTION_EVENTS_DAYS.
  Los abiertos no se borran nunca.
- Alertas resueltas, comandos terminados y vulnerabilidades resueltas:
  RETENTION_RESOLVED_DAYS.

Los ajustes se leen en cada corrida: un cambio en Configuracion aplica en la
proxima purga (o con "Aplicar ahora").
"""

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select, text

from app.core.config import settings
from app.core.db import SessionLocal
from app.models.alert import Alert
from app.models.security import AuthAttempt, Command, IngestedRequest, SecurityEvent
from app.models.vulnerability import VulnerabilityFinding

logger = logging.getLogger("retention")

COMPRESS_AFTER = "7 days"
FIRST_RUN_DELAY_SECONDS = 600
RUN_EVERY_SECONDS = 86400
_last_result: dict = {}


async def ensure_metrics_compression(conn) -> None:
    """Activa el columnstore en metrics y su politica de compresion, una sola
    vez. add_columnstore_policy reemplaza a add_compression_policy (obsoleta
    desde TimescaleDB 2.18)."""
    enabled = (
        await conn.execute(text(
            "SELECT compression_enabled FROM timescaledb_information.hypertables WHERE hypertable_name = 'metrics'"
        ))
    ).scalar_one_or_none()
    if enabled is None:
        return
    if not enabled:
        await conn.execute(text(
            "ALTER TABLE metrics SET (timescaledb.enable_columnstore = true, timescaledb.segmentby = 'host_id')"
        ))
    has_policy = (
        await conn.execute(text(
            "SELECT 1 FROM timescaledb_information.jobs WHERE hypertable_name = 'metrics' AND proc_name = 'policy_compression'"
        ))
    ).scalar_one_or_none()
    if not has_policy:
        await conn.execute(text(f"CALL add_columnstore_policy('metrics', after => INTERVAL '{COMPRESS_AFTER}')"))


async def purge() -> dict:
    now = datetime.now(timezone.utc)
    requests_cut = now - timedelta(days=settings.retention_requests_days)
    events_cut = now - timedelta(days=settings.retention_events_days)
    resolved_cut = now - timedelta(days=settings.retention_resolved_days)
    counts: dict[str, int] = {}
    async with SessionLocal() as session:
        dropped = (
            await session.execute(
                text("SELECT count(*) FROM drop_chunks('metrics', older_than => make_interval(days => :d))"),
                {"d": settings.retention_metrics_days},
            )
        ).scalar_one()
        counts["metrics (bloques de tiempo)"] = dropped

        async def run(label: str, stmt) -> None:
            counts[label] = (await session.execute(stmt)).rowcount or 0

        await run("peticiones HTTP", delete(IngestedRequest).where(IngestedRequest.ts < requests_cut))
        await run("intentos de login", delete(AuthAttempt).where(AuthAttempt.ts < requests_cut))

        old_events = select(SecurityEvent.id).where(SecurityEvent.status != "open", SecurityEvent.created_at < events_cut)
        # Los comandos apuntan al evento (foreign key): van primero.
        await run("comandos de eventos viejos", delete(Command).where(Command.security_event_id.in_(old_events)))
        await run("eventos de seguridad cerrados", delete(SecurityEvent).where(
            SecurityEvent.status != "open", SecurityEvent.created_at < events_cut))
        await run("comandos terminados", delete(Command).where(
            Command.status.in_(("done", "failed")), Command.created_at < resolved_cut))
        await run("alertas resueltas", delete(Alert).where(Alert.status == "resolved", Alert.triggered_at < resolved_cut))
        await run("vulnerabilidades resueltas", delete(VulnerabilityFinding).where(
            VulnerabilityFinding.status == "resolved", VulnerabilityFinding.resolved_at < resolved_cut))
        await session.commit()

    _last_result.clear()
    _last_result.update({"at": now.isoformat(), "deleted": counts})
    if any(counts.values()):
        logger.info("Purga de retencion: %s", ", ".join(f"{k}: {v}" for k, v in counts.items() if v))
    return counts


async def sizes() -> dict:
    async with SessionLocal() as session:
        rows = (await session.execute(text("""
            SELECT relname, n_live_tup, pg_total_relation_size(relid)
            FROM pg_stat_user_tables
            WHERE relname IN ('ingested_requests', 'auth_attempts', 'security_events', 'alerts',
                              'commands', 'vulnerability_findings', 'installed_packages')
        """))).all()
        metrics = (await session.execute(text(
            "SELECT hypertable_size('metrics'), (SELECT count(*) FROM metrics), (SELECT min(ts) FROM metrics)"
        ))).one()
        total = (await session.execute(text("SELECT pg_database_size(current_database())"))).scalar_one()
    tables = [{"table": "metrics", "rows": metrics[1], "bytes": metrics[0] or 0,
               "oldest": metrics[2].isoformat() if metrics[2] else None}]
    tables += [{"table": r[0], "rows": r[1], "bytes": r[2], "oldest": None} for r in rows]
    return {"database_bytes": total, "tables": sorted(tables, key=lambda t: -t["bytes"]), "last_purge": dict(_last_result)}


async def run_forever() -> None:
    await asyncio.sleep(FIRST_RUN_DELAY_SECONDS)
    while True:
        try:
            await purge()
        except Exception:
            logger.exception("Fallo la purga de retencion")
        await asyncio.sleep(RUN_EVERY_SECONDS)
