from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.core.db import get_db
from app.models.alert import Alert
from app.models.host import Host
from app.models.metric import Metric
from app.models.security import BlockedIP, SecurityEvent
from app.models.vulnerability import VulnerabilityFinding
from app.schemas.alert import AskRequest
from app.services import ai

router = APIRouter(prefix="/api/v1/ai", tags=["ai"])


async def _host_context(db: AsyncSession, host_id: str) -> list[str]:
    since = datetime.now(timezone.utc) - timedelta(hours=1)
    parts: list[str] = []

    host = (await db.execute(select(Host).where(Host.id == host_id))).scalar_one_or_none()
    if not host:
        return parts

    parts.append(f"Host: {host.name} ({host.hostname})")
    metrics = (
        await db.execute(
            select(Metric).where(Metric.host_id == host.id, Metric.ts >= since).order_by(Metric.ts.desc()).limit(20)
        )
    ).scalars().all()
    for m in metrics:
        parts.append(f"[{m.ts}] cpu={m.cpu_percent} mem={m.mem_percent} disk={m.disk_percent} load1={m.load1}")
    alerts = (
        await db.execute(
            select(Alert).where(Alert.host_id == host.id).order_by(Alert.triggered_at.desc()).limit(10)
        )
    ).scalars().all()
    for a in alerts:
        parts.append(f"Alerta [{a.status}] valor={a.value} en {a.triggered_at}")
    return parts


async def _security_context(db: AsyncSession) -> list[str]:
    parts: list[str] = []
    events = (
        await db.execute(select(SecurityEvent).order_by(SecurityEvent.created_at.desc()).limit(25))
    ).scalars().all()
    for e in events:
        geo = f" ({e.geo_city or ''} {e.geo_country})" if e.geo_country else ""
        parts.append(
            f"[{e.created_at}] {e.kind} severidad={e.severity} origen={e.source_ip}{geo} "
            f"estado={e.status} accion_sugerida={e.suggested_action} resumen_ia={e.ai_summary or '(pendiente)'}"
        )
    blocked = (
        await db.execute(select(BlockedIP).where(BlockedIP.unblocked_at.is_(None)).order_by(BlockedIP.blocked_at.desc()).limit(20))
    ).scalars().all()
    for b in blocked:
        parts.append(f"IP bloqueada: {b.ip} desde {b.blocked_at} motivo={b.reason or '(sin motivo)'}")
    return parts


async def _vulnerabilities_context(db: AsyncSession) -> list[str]:
    parts: list[str] = []
    findings = (
        await db.execute(
            select(VulnerabilityFinding).where(VulnerabilityFinding.status == "open").order_by(VulnerabilityFinding.last_seen.desc()).limit(30)
        )
    ).scalars().all()
    for f in findings:
        parts.append(
            f"{f.package_name} {f.package_version}: {f.vuln_id} severidad={f.severity} "
            f"fix_disponible={f.fixed_version or 'no'} (host_id={f.host_id})"
        )
    return parts


async def _build_context(db: AsyncSession, host_id: str | None, scope: str | None) -> str:
    if host_id:
        parts = await _host_context(db, host_id)
    elif scope == "security":
        parts = await _security_context(db)
    elif scope == "vulnerabilities":
        parts = await _vulnerabilities_context(db)
    else:
        alerts = (await db.execute(select(Alert).order_by(Alert.triggered_at.desc()).limit(20))).scalars().all()
        parts = [f"Alerta host={a.host_id} [{a.status}] valor={a.value} en {a.triggered_at}" for a in alerts]

    return "\n".join(parts) if parts else "No hay datos recientes."


@router.post("/ask", dependencies=[Depends(get_current_user)])
async def ask(payload: AskRequest, db: AsyncSession = Depends(get_db)):
    context = await _build_context(db, payload.host_id, payload.scope)
    prompt = f"Contexto:\n{context}\n\nPregunta: {payload.question}"
    answer = await ai.ask(prompt, backend=payload.backend)
    return {"answer": answer}
