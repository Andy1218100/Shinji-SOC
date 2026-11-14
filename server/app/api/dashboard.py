from fastapi import APIRouter, Depends, Request
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_admin
from app.core.db import get_db
from app.models.alert import Alert
from app.models.host import Host
from app.models.metric import Metric
from app.models.user import User
from app.services import geoip

router = APIRouter(tags=["dashboard"])
templates = Jinja2Templates(directory="app/templates")


def host_status(metric: Metric | None) -> str:
    if metric is None:
        return "idle"
    values = [v for v in (metric.cpu_percent, metric.mem_percent, metric.disk_percent) if v is not None]
    if not values:
        return "idle"
    peak = max(values)
    if peak >= 90:
        return "crit"
    if peak >= 75:
        return "warn"
    return "ok"


@router.get("/")
async def index(request: Request, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    hosts = (await db.execute(select(Host).order_by(Host.name))).scalars().all()

    latest_by_host = {}
    status_by_host = {}
    for host in hosts:
        metric = (
            await db.execute(
                select(Metric).where(Metric.host_id == host.id).order_by(Metric.ts.desc()).limit(1)
            )
        ).scalar_one_or_none()
        latest_by_host[host.id] = metric
        status_by_host[host.id] = host_status(metric)

    alerts = (
        await db.execute(select(Alert).where(Alert.status == "firing").order_by(Alert.triggered_at.desc()))
    ).scalars().all()
    host_name_by_id = {host.id: host.name for host in hosts}

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "hosts": hosts,
            "latest": latest_by_host,
            "status_by_host": status_by_host,
            "alerts": alerts,
            "host_name_by_id": host_name_by_id,
            "active_nav": "monitoreo",
            "user": user,
        },
    )


@router.get("/hosts/{host_id}")
async def host_detail(
    request: Request, host_id: str, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)
):
    host = (await db.execute(select(Host).where(Host.id == host_id))).scalar_one_or_none()
    return templates.TemplateResponse(
        "host.html", {"request": request, "host": host, "active_nav": "monitoreo", "user": user}
    )


@router.get("/security")
async def security_page(request: Request, user: User = Depends(get_current_user)):
    return templates.TemplateResponse(
        "security.html",
        {
            "request": request,
            "active_nav": "seguridad",
            "user": user,
            "geoip_configured": geoip.is_configured(),
        },
    )


@router.get("/vulnerabilities")
async def vulnerabilities_page(request: Request, user: User = Depends(get_current_user)):
    return templates.TemplateResponse(
        "vulnerabilities.html", {"request": request, "active_nav": "vulnerabilidades", "user": user}
    )


@router.get("/users")
async def users_page(request: Request, user: User = Depends(require_admin)):
    return templates.TemplateResponse(
        "users.html", {"request": request, "active_nav": "usuarios", "user": user}
    )


@router.get("/login")
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})
