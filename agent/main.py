"""Agente Prox Secure: un solo proceso con varias tareas concurrentes.

- metrics_loop: CPU/mem/disco/red del host (siempre activo).
- logs_loop: tail de logs de acceso web, para el motor IDS del servidor.
- process_loop: vigilancia de cuentas de servicio (webshell/RCE).
- commands_loop: ejecuta bloqueos/kills aprobados desde el panel.

Corre sin privilegios salvo las acciones puntuales de commands.py, que
usan sudo acotado (ver sudoers/prox-secure-agent).
"""

import asyncio
import logging

import httpx

import commands
import config
import log_tailer
import metrics
import process_watch

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("agent")


async def metrics_loop(client: httpx.AsyncClient, base_url: str, headers: dict, interval: int) -> None:
    while True:
        try:
            resp = await client.post(f"{base_url}/api/v1/ingest", json=metrics.collect(), headers=headers)
            resp.raise_for_status()
        except Exception:
            logger.exception("Fallo enviando metricas")
        await asyncio.sleep(interval)


async def logs_loop(client: httpx.AsyncClient, base_url: str, headers: dict, log_paths: list[str]) -> None:
    if not log_paths:
        return
    while True:
        try:
            entries = log_tailer.read_new_entries(log_paths)
            if entries:
                resp = await client.post(
                    f"{base_url}/api/v1/logs/ingest", json={"entries": entries}, headers=headers
                )
                resp.raise_for_status()
        except Exception:
            logger.exception("Fallo enviando logs")
        await asyncio.sleep(10)


async def process_loop(client: httpx.AsyncClient, base_url: str, headers: dict, pw_config: dict) -> None:
    service_users = pw_config.get("service_users") or []
    interval = pw_config.get("interval_seconds", 10)
    if not service_users:
        return
    while True:
        try:
            anomalies = process_watch.scan(service_users)
            if anomalies:
                resp = await client.post(
                    f"{base_url}/api/v1/process-events/ingest", json={"events": anomalies}, headers=headers
                )
                resp.raise_for_status()
        except Exception:
            logger.exception("Fallo vigilando procesos")
        await asyncio.sleep(interval)


async def commands_loop(
    client: httpx.AsyncClient, base_url: str, headers: dict, interval: int, fail2ban_jail: str
) -> None:
    while True:
        try:
            await commands.poll_and_execute(client, base_url, headers, fail2ban_jail)
        except Exception:
            logger.exception("Fallo consultando/ejecutando comandos")
        await asyncio.sleep(interval)


async def main() -> None:
    cfg = config.load()
    base_url = cfg["server_url"].rstrip("/")
    headers = {"X-API-Key": cfg["api_key"]}

    logger.info("Agente Prox Secure iniciado, servidor=%s", base_url)

    async with httpx.AsyncClient(timeout=30) as client:
        await asyncio.gather(
            metrics_loop(client, base_url, headers, cfg["metrics_interval_seconds"]),
            logs_loop(client, base_url, headers, cfg["log_paths"]),
            process_loop(client, base_url, headers, cfg["process_watch"]),
            commands_loop(client, base_url, headers, cfg["command_poll_interval_seconds"], cfg["fail2ban_jail"]),
        )


if __name__ == "__main__":
    asyncio.run(main())
