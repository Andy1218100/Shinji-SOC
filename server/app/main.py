import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.api import ai, alerts, auth, commands, dashboard, hosts, logs, metrics, security, vulnerabilities
from app.core.db import Base, engine
from app.services.alerting import run_forever as alerting_run_forever
from app.services.vuln_scan import run_forever as vuln_scan_run_forever

logging.basicConfig(level=logging.INFO)


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    tasks = [
        asyncio.create_task(alerting_run_forever()),
        asyncio.create_task(vuln_scan_run_forever()),
    ]
    yield
    for task in tasks:
        task.cancel()


app = FastAPI(title="Prox Secure", lifespan=lifespan)
app.mount("/static", StaticFiles(directory="app/static"), name="static")

app.include_router(dashboard.router)
app.include_router(hosts.router)
app.include_router(metrics.router)
app.include_router(alerts.router)
app.include_router(ai.router)
app.include_router(logs.router)
app.include_router(security.router)
app.include_router(commands.router)
app.include_router(auth.router)
app.include_router(vulnerabilities.router)
