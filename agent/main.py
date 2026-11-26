"""Agente Shinji SOC: un solo proceso con varias tareas concurrentes.

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
- waf_loop: lo que detecta el WAF opcional (waf.sh), si esta instalado.

Corre sin privilegios salvo las acciones puntuales de commands.py, que
usan sudo acotado (ver sudoers/shinji-soc-agent).
"""

import asyncio
import os
import logging

import httpx

import commands
import config
import conn_watch
import discovery
import inventory
import auth_watch
import log_tailer
import metrics
import process_watch
import waf_watch

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


async def logs_loop(client: httpx.AsyncClient, base_url: str, headers: dict, watch: dict) -> None:
    """watch["log_paths"] lo actualiza discovery_loop: un sitio web nuevo se
    empieza a vigilar en el siguiente descubrimiento, sin reiniciar."""
    while True:
        try:
            while watch["log_paths"]:
                entries = await asyncio.to_thread(log_tailer.read_new_entries, watch["log_paths"])
                if entries:
                    resp = await client.post(
                        f"{base_url}/api/v1/logs/ingest", json={"entries": entries}, headers=headers
                    )
                    resp.raise_for_status()
                if len(entries) < log_tailer.MAX_ENTRIES_PER_READ:
                    break  # al dia; si no, sigue mandando el atraso
        except Exception:
            logger.exception("Fallo enviando logs")
        await asyncio.sleep(10)


async def auth_loop(client: httpx.AsyncClient, base_url: str, headers: dict) -> None:
    """Intentos de login por SSH y en la interfaz web de Proxmox (ver
    auth_watch). Si el host no tiene journal legible ni auth.log, no hace nada."""
    source = await asyncio.to_thread(auth_watch.detect_source)
    if not source:
        logger.warning("Sin journal legible ni /var/log/auth.log: no se vigilan los logins SSH")
        return
    logger.info("Vigilando logins SSH/Proxmox desde %s", source)
    while True:
        try:
            entries = await asyncio.to_thread(auth_watch.read_new_entries, source)
            for start in range(0, len(entries), 1000):
                resp = await client.post(
                    f"{base_url}/api/v1/auth-events/ingest", json={"entries": entries[start:start + 1000]}, headers=headers
                )
                resp.raise_for_status()
        except Exception:
            logger.exception("Fallo enviando intentos de login")
        await asyncio.sleep(15)


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


async def discovery_loop(client: httpx.AsyncClient, base_url: str, headers: dict, interval: int,
                         watch: dict, manual_log_paths: bool) -> None:
    while True:
        await asyncio.sleep(interval)
        report = await send_system_report(client, base_url, headers)
        if not manual_log_paths:
            new_paths = report.get("log_paths", [])
            if new_paths != watch["log_paths"]:
                logger.info("Logs de acceso a vigilar actualizados: %s", new_paths)
                watch["log_paths"] = new_paths


# Si el envio falla (servidor reiniciandose, red), reintentar pronto: con
# el intervalo normal (1 dia) un corte justo al arrancar el agente dejaba
# el host un dia entero con el inventario viejo (paso en un host real).
INVENTORY_RETRY_SECONDS = 300


async def inventory_loop(client: httpx.AsyncClient, base_url: str, headers: dict, interval: int) -> None:
    while True:
        wait = interval
        try:
            await inventory.send(client, base_url, headers)
        except Exception:
            logger.exception("Fallo enviando inventario de paquetes, reintento en %ss", INVENTORY_RETRY_SECONDS)
            wait = min(interval, INVENTORY_RETRY_SECONDS)
        await asyncio.sleep(wait)


async def connections_loop(client: httpx.AsyncClient, base_url: str, headers: dict, interval: int) -> None:
    tracker = conn_watch.Tracker()
    interval = max(interval, 10)
    while True:
        try:
            listeners, outbound = await asyncio.to_thread(conn_watch.snapshot)
            body = tracker.payload(listeners, outbound)
            if body:
                resp = await client.post(f"{base_url}/api/v1/connections/ingest", json=body, headers=headers)
                if resp.status_code == 404:
                    # Panel de una version sin este endpoint: no insistir.
                    logger.warning("El panel no recibe conexiones (version anterior); se desactiva este monitoreo")
                    return
                resp.raise_for_status()
        except Exception:
            logger.exception("Fallo vigilando conexiones")
        await asyncio.sleep(interval)


async def waf_loop(client: httpx.AsyncClient, base_url: str, headers: dict) -> None:
    """Lo que detecta el WAF opcional (agent/waf.sh). Si no esta instalado,
    revisa cada minuto por si se instala despues."""
    announced = False
    while True:
        try:
            if waf_watch.available():
                if not announced:
                    logger.info("Leyendo lo que detecta el WAF desde %s", waf_watch.AUDIT_LOG)
                    announced = True
                while True:
                    entries = await asyncio.to_thread(waf_watch.read_new_entries)
                    if entries:
                        resp = await client.post(
                            f"{base_url}/api/v1/waf/ingest",
                            json={"mode": waf_watch.mode(), "entries": entries}, headers=headers,
                        )
                        if resp.status_code == 404:
                            logger.warning("El panel no recibe eventos del WAF (version anterior); se desactiva")
                            return
                        resp.raise_for_status()
                    if len(entries) < waf_watch.MAX_ENTRIES_PER_READ:
                        break
        except Exception:
            logger.exception("Fallo enviando lo detectado por el WAF")
        await asyncio.sleep(10 if waf_watch.available() else 60)


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

    logger.info("Agente Shinji SOC iniciado, servidor=%s", base_url)

    # Panel con HTTPS de una CA propia (certificado no publico):
    # SHINJI_SOC_CA_FILE apunta a su certificado raiz. Sin la variable se
    # usan las CAs del sistema (sirve para Let's Encrypt y para http://).
    verify = os.environ.get("SHINJI_SOC_CA_FILE") or True
    async with httpx.AsyncClient(timeout=30, verify=verify) as client:
        # Lo primero que hace el agente, antes de arrancar a monitorear:
        # describir el sistema. El resto de los loops usa ese resultado
        # para personalizarse a este host en particular.
        report = await send_system_report(client, base_url, headers)

        log_paths = cfg["log_paths"] or report.get("log_paths", [])
        if not cfg["log_paths"]:
            logger.info("log_paths autodetectados para este host: %s", log_paths)
            if report.get("other_log_paths_total"):
                logger.info("%s logs mas encontrados que no son de acceso web: no se leen",
                            report["other_log_paths_total"])
        watch = {"log_paths": log_paths}

        process_watch_cfg = dict(cfg["process_watch"])
        if not process_watch_cfg.get("service_users"):
            process_watch_cfg["service_users"] = report.get("service_accounts", [])
            if process_watch_cfg["service_users"]:
                logger.info("Cuentas de servicio autodetectadas: %s", process_watch_cfg["service_users"])

        conn_cfg = cfg.get("connections") or {}
        await asyncio.gather(
            metrics_loop(client, base_url, headers, cfg["metrics_interval_seconds"]),
            logs_loop(client, base_url, headers, watch),
            process_loop(client, base_url, headers, process_watch_cfg),
            auth_loop(client, base_url, headers),
            inventory_loop(client, base_url, headers, cfg["inventory_interval_seconds"]),
            discovery_loop(client, base_url, headers, cfg["discovery_interval_seconds"], watch, bool(cfg["log_paths"])),
            commands_loop(client, base_url, headers, cfg["command_poll_interval_seconds"], cfg["fail2ban_jail"]),
            waf_loop(client, base_url, headers),
            *([connections_loop(client, base_url, headers, int(conn_cfg.get("interval_seconds", 60)))]
              if conn_cfg.get("enabled", True) else []),
        )


if __name__ == "__main__":
    asyncio.run(main())
