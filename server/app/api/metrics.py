from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import cast, func, select, text
from sqlalchemy.dialects.postgresql import INTERVAL
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_host, get_current_user
from app.core.db import get_db
from app.models.host import Host
from app.models.metric import Metric
from app.schemas.metric import MetricIn, MetricOut

router = APIRouter(prefix="/api/v1", tags=["metrics"])

_NUMERIC_FIELDS = [f for f in MetricIn.model_fields if f != "ts"]

# Rango -> cuanto mirar hacia atras. El ancho del bucket de downsampling se
# calcula para que cada rango devuelva ~250 puntos como mucho, sin importar
# cuanto tiempo abarque -- asi un grafico de 30 dias no manda 170mil filas.
RANGE_SECONDS: dict[str, int] = {
    "1m": 60, "5m": 300, "15m": 900, "30m": 1800,
    "1h": 3600, "3h": 10800, "6h": 21600, "12h": 43200,
    "24h": 86400, "3d": 259200, "7d": 604800, "30d": 2592000,
}
TARGET_POINTS = 250


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


@router.get("/hosts/{host_id}/metrics", response_model=list[MetricOut], dependencies=[Depends(get_current_user)])
async def get_metrics(
    host_id: str,
    range: str = Query(default="1h"),
    db: AsyncSession = Depends(get_db),
):
    seconds = RANGE_SECONDS.get(range, RANGE_SECONDS["1h"])
    since = datetime.now(timezone.utc) - timedelta(seconds=seconds)
    bucket_seconds = max(1, seconds // TARGET_POINTS)

    if bucket_seconds <= 15:
        # Rango corto: los puntos crudos ya entran comodos, no hace falta
        # agregar (y se conserva el id real de cada fila).
        result = await db.execute(
            select(Metric).where(Metric.host_id == host_id, Metric.ts >= since).order_by(Metric.ts)
        )
        return [
            MetricOut(id=str(m.id), host_id=str(m.host_id), ts=m.ts, **{f: getattr(m, f) for f in _NUMERIC_FIELDS})
            for m in result.scalars().all()
        ]

    # time_bucket() exige un INTERVAL real, no un VARCHAR -- bucket_seconds
    # es siempre un int calculado por el servidor, nunca viene del request.
    bucket = func.time_bucket(cast(text(f"'{bucket_seconds} seconds'"), INTERVAL), Metric.ts)
    stmt = (
        select(bucket.label("bucket_ts"), *[func.avg(getattr(Metric, f)).label(f) for f in _NUMERIC_FIELDS])
        .where(Metric.host_id == host_id, Metric.ts >= since)
        .group_by(bucket)
        .order_by(bucket)
    )
    rows = (await db.execute(stmt)).all()
    return [
        MetricOut(host_id=host_id, ts=row.bucket_ts, **{f: getattr(row, f) for f in _NUMERIC_FIELDS})
        for row in rows
    ]
