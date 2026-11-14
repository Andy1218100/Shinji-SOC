import asyncio
import logging
from contextlib import asynccontextmanager
from urllib.parse import quote

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from app.api import ai, alerts, auth, commands, dashboard, hosts, logs, metrics, security, users, vulnerabilities
from app.api.deps import Forbidden, NotAuthenticated
from app.core.db import Base, engine, ensure_hypertables
from app.services.alerting import run_forever as alerting_run_forever
from app.services.vuln_scan import run_forever as vuln_scan_run_forever

logging.basicConfig(level=logging.INFO)


async def _connect_with_retry(max_attempts: int = 10, delay_seconds: float = 2.0) -> None:
    for attempt in range(1, max_attempts + 1):
        try:
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
                await ensure_hypertables(conn)
            return
        except Exception as exc:
            if attempt == max_attempts:
                raise
            logging.warning(
                "No se pudo conectar a la base de datos (intento %s/%s): %s. Reintentando en %ss...",
                attempt, max_attempts, exc, delay_seconds,
            )
            await asyncio.sleep(delay_seconds)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await _connect_with_retry()
    tasks = [
        asyncio.create_task(alerting_run_forever()),
        asyncio.create_task(vuln_scan_run_forever()),
    ]
    yield
    for task in tasks:
        task.cancel()


app = FastAPI(title="Prox Secure", lifespan=lifespan)
app.mount("/static", StaticFiles(directory="app/static"), name="static")


@app.exception_handler(NotAuthenticated)
async def handle_not_authenticated(request: Request, exc: NotAuthenticated):
    if request.url.path.startswith("/api/"):
        return JSONResponse(status_code=401, content={"detail": "No autenticado"})
    next_path = quote(request.url.path)
    return RedirectResponse(f"/login?next={next_path}", status_code=303)


@app.exception_handler(Forbidden)
async def handle_forbidden(request: Request, exc: Forbidden):
    if request.url.path.startswith("/api/"):
        return JSONResponse(status_code=403, content={"detail": "No autorizado para este rol"})
    return RedirectResponse("/", status_code=303)


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
app.include_router(users.router)
