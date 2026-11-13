from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
from app.models.alert import Alert
from app.models.host import Host
from app.models.metric import Metric
from app.schemas.alert import AskRequest
from app.services import ai

router = APIRouter(prefix="/api/v1/ai", tags=["ai"])


async def _build_context(db: AsyncSession, host_id: str | None) -> str:
    since = datetime.now(timezone.utc) - timedelta(hours=1)
    parts: list[str] = []

    if host_id:
        host = (await db.execute(select(Host).where(Host.id == host_id))).scalar_one_or_none()
        if host:
            parts.append(f"Host: {host.name} ({host.hostname})")
            metrics = (
                await db.execute(
                    select(Metric)
                    .where(Metric.host_id == host.id, Metric.ts >= since)
                    .order_by(Metric.ts.desc())
                    .limit(20)
                )
            ).scalars().all()
            for m in metrics:
                parts.append(
                    f"[{m.ts}] cpu={m.cpu_percent} mem={m.mem_percent} disk={m.disk_percent} load1={m.load1}"
                )
            alerts = (
                await db.execute(
                    select(Alert).where(Alert.host_id == host.id).order_by(Alert.triggered_at.desc()).limit(10)
                )
            ).scalars().all()
            for a in alerts:
                parts.append(f"Alerta [{a.status}] valor={a.value} en {a.triggered_at}")
    else:
        alerts = (await db.execute(select(Alert).order_by(Alert.triggered_at.desc()).limit(20))).scalars().all()
        for a in alerts:
            parts.append(f"Alerta host={a.host_id} [{a.status}] valor={a.value} en {a.triggered_at}")

    return "\n".join(parts) if parts else "No hay datos recientes."


@router.post("/ask")
async def ask(payload: AskRequest, db: AsyncSession = Depends(get_db)):
    context = await _build_context(db, payload.host_id)
    prompt = f"Contexto:\n{context}\n\nPregunta: {payload.question}"
    answer = await ai.ask(prompt, backend=payload.backend)
    return {"answer": answer}
