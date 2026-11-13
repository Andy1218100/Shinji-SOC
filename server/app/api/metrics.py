from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_host
from app.core.db import get_db
from app.models.host import Host
from app.models.metric import Metric
from app.schemas.metric import MetricIn, MetricOut

router = APIRouter(prefix="/api/v1", tags=["metrics"])


@router.post("/ingest", status_code=201)
async def ingest(
    payload: MetricIn,
    host: Host = Depends(get_current_host),
    db: AsyncSession = Depends(get_db),
):
    metric = Metric(host_id=host.id, ts=payload.ts or datetime.now(timezone.utc), **payload.model_dump(exclude={"ts"}))
    db.add(metric)
    host.last_seen = metric.ts
    await db.commit()
    return {"status": "ok"}


@router.get("/hosts/{host_id}/metrics", response_model=list[MetricOut])
async def get_metrics(
    host_id: str,
    minutes: int = Query(default=60, le=1440),
    db: AsyncSession = Depends(get_db),
):
    since = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    result = await db.execute(
        select(Metric).where(Metric.host_id == host_id, Metric.ts >= since).order_by(Metric.ts)
    )
    metrics = result.scalars().all()
    return [
        MetricOut(id=str(m.id), host_id=str(m.host_id), ts=m.ts, **{
            k: getattr(m, k) for k in MetricIn.model_fields if k != "ts"
        })
        for m in metrics
    ]
