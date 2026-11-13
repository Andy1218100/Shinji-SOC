import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.api import ai, alerts, commands, dashboard, hosts, logs, metrics, security
from app.core.db import Base, engine
from app.services.alerting import run_forever

logging.basicConfig(level=logging.INFO)


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    task = asyncio.create_task(run_forever())
    yield
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
