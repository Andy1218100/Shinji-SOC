"""Agente Prox Secure: un solo proceso con varias tareas concurrentes.

- discovery: lo primero que hace el agente al arrancar es describir el
  sistema (SO, hardware, servicios, puertos) y mandarlo al servidor, que
  arma un informe con la IA local. Esos mismos datos se usan para
  personalizar que logs y que cuentas de servicio vigila ESTE host, en
  vez de depender de que el admin los tipee a mano para cada maquina
  (log_paths/process_watch.service_users en config.yaml siguen
  funcionando como override manual si estan definidos).
- metrics_loop: CPU/mem/disco/red del host (siempre activo).
- logs_loop: tail de logs de acceso web, para el motor IDS del servidor.
- process_loop: vigilancia de cuentas de servicio (webshell/RCE).
- inventory_loop: paquetes instalados (dpkg), una vez al dia por defecto,
  para que el servidor los cruce contra OSV.dev.
- discovery_loop: repite el descubrimiento una vez al dia (por si se
  instala un servicio nuevo despues) y reenvia el informe.
- commands_loop: ejecuta bloqueos/kills aprobados desde el panel.

Corre sin privilegios salvo las acciones puntuales de commands.py, que
usan sudo acotado (ver sudoers/prox-secure-agent).
"""

import asyncio
import logging

import httpx

import commands
import config
import discovery
import inventory
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


async def send_system_report(client: httpx.AsyncClient, base_url: str, headers: dict) -> dict:
    report = discovery.full_report()
    try:
        resp = await client.post(f"{base_url}/api/v1/system-report/ingest", json=report, headers=headers)
        resp.raise_for_status()
        logger.info("Informe de sistema enviado")
    except Exception:
        logger.exception("Fallo enviando el informe de sistema")
    return report


async def discovery_loop(client: httpx.AsyncClient, base_url: str, headers: dict, interval: int) -> None:
    while True:
        await asyncio.sleep(interval)
        await send_system_report(client, base_url, headers)


async def inventory_loop(client: httpx.AsyncClient, base_url: str, headers: dict, interval: int) -> None:
    while True:
        try:
            packages = inventory.collect()
            if packages:
                payload = {"packages": packages, "debian_release": inventory.debian_release()}
                resp = await client.post(
                    f"{base_url}/api/v1/inventory/ingest", json=payload, headers=headers
                )
                resp.raise_for_status()
        except Exception:
            logger.exception("Fallo enviando inventario de paquetes")
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
        # Lo primero que hace el agente, antes de arrancar a monitorear:
        # describir el sistema. El resto de los loops usa ese resultado
        # para personalizarse a este host en particular.
        report = await send_system_report(client, base_url, headers)

        log_paths = cfg["log_paths"] or report.get("log_paths", [])
        if not cfg["log_paths"] and log_paths:
            logger.info("log_paths autodetectados para este host: %s", log_paths)

        process_watch_cfg = dict(cfg["process_watch"])
        if not process_watch_cfg.get("service_users"):
            process_watch_cfg["service_users"] = report.get("service_accounts", [])
            if process_watch_cfg["service_users"]:
                logger.info("Cuentas de servicio autodetectadas: %s", process_watch_cfg["service_users"])

        await asyncio.gather(
            metrics_loop(client, base_url, headers, cfg["metrics_interval_seconds"]),
            logs_loop(client, base_url, headers, log_paths),
            process_loop(client, base_url, headers, process_watch_cfg),
            inventory_loop(client, base_url, headers, cfg["inventory_interval_seconds"]),
            discovery_loop(client, base_url, headers, cfg["discovery_interval_seconds"]),
            commands_loop(client, base_url, headers, cfg["command_poll_interval_seconds"], cfg["fail2ban_jail"]),
        )


if __name__ == "__main__":
    asyncio.run(main())
