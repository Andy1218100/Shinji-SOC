from fastapi import APIRouter, Depends, Request
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
from app.models.alert import Alert
from app.models.host import Host
from app.models.metric import Metric

router = APIRouter(tags=["dashboard"])
templates = Jinja2Templates(directory="app/templates")


@router.get("/")
async def index(request: Request, db: AsyncSession = Depends(get_db)):
    hosts = (await db.execute(select(Host).order_by(Host.name))).scalars().all()

    latest_by_host = {}
    for host in hosts:
        metric = (
            await db.execute(
                select(Metric).where(Metric.host_id == host.id).order_by(Metric.ts.desc()).limit(1)
            )
        ).scalar_one_or_none()
        latest_by_host[host.id] = metric

    alerts = (
        await db.execute(select(Alert).where(Alert.status == "firing").order_by(Alert.triggered_at.desc()))
    ).scalars().all()

    return templates.TemplateResponse(
        "index.html",
        {"request": request, "hosts": hosts, "latest": latest_by_host, "alerts": alerts},
    )


@router.get("/hosts/{host_id}")
async def host_detail(request: Request, host_id: str, db: AsyncSession = Depends(get_db)):
    host = (await db.execute(select(Host).where(Host.id == host_id))).scalar_one_or_none()
    return templates.TemplateResponse("host.html", {"request": request, "host": host})
