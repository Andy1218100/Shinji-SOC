"""Ejecuta comandos aprobados por el administrador desde el panel
(bloquear IP via fail2ban, terminar un proceso, dar acceso de lectura a
un log bloqueado) usando los permisos acotados definidos en
sudoers/prox-secure-agent. El agente en si corre sin privilegios; solo
esas acciones puntuales usan sudo.
"""

import logging
import os
import subprocess

import httpx

import discovery
import inventory

logger = logging.getLogger("commands")

AGENT_DIR = os.path.dirname(os.path.abspath(__file__))


def _run(args: list[str]) -> tuple[bool, str]:
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=30)
        output = (result.stdout + result.stderr).strip()[:2000]
        return result.returncode == 0, output
    except Exception as exc:
        return False, str(exc)[:2000]


def execute(command: dict, fail2ban_jail: str) -> tuple[bool, str]:
    action = command["action"]
    payload = command.get("payload") or {}

    if action == "block_ip":
        return _run(["sudo", "/usr/bin/fail2ban-client", "set", fail2ban_jail, "banip", payload["ip"]])

    if action == "unblock_ip":
        return _run(["sudo", "/usr/bin/fail2ban-client", "set", fail2ban_jail, "unbanip", payload["ip"]])

    if action == "kill_process":
        expected = (payload.get("cmdline") or "")[:80]
        return _run(["sudo", f"{AGENT_DIR}/kill_process.sh", str(payload["pid"]), expected])

    if action == "grant_log_access":
        return _run(["sudo", f"{AGENT_DIR}/grant_log_access.sh", payload["path"]])

    return False, f"accion desconocida: {action}"


async def poll_and_execute(client: httpx.AsyncClient, base_url: str, headers: dict, fail2ban_jail: str) -> None:
    resp = await client.get(f"{base_url}/api/v1/commands/pending", headers=headers)
    resp.raise_for_status()
    commands = resp.json()

    granted_access = False
    for command in commands:
        if command["action"] == "send_inventory":
            # "Escanear ahora" del panel: el servidor escanea apenas recibe
            # el inventario, con las versiones de este momento (despues de
            # un apt upgrade, por ejemplo), no las del ultimo envio diario.
            try:
                count = await inventory.send(client, base_url, headers)
                ok, output = True, f"inventario enviado: {count} paquetes"
            except Exception as exc:
                ok, output = False, f"fallo enviando inventario: {exc}"[:2000]
        else:
            ok, output = execute(command, fail2ban_jail)
        logger.info("Comando %s (%s): %s -> %s", command["id"], command["action"], ok, output)
        await client.post(
            f"{base_url}/api/v1/commands/{command['id']}/result",
            headers=headers,
            json={"status": "done" if ok else "failed", "result": output},
        )
        if command["action"] == "grant_log_access" and ok:
            granted_access = True

    if granted_access:
        # Releer el sistema ahora, no esperar al proximo ciclo diario de
        # discovery -- el admin acaba de dar un permiso especificamente
        # para que esto se vea reflejado.
        try:
            report = discovery.full_report()
            resp = await client.post(f"{base_url}/api/v1/system-report/ingest", json=report, headers=headers)
            resp.raise_for_status()
            logger.info("Informe de sistema reenviado tras otorgar acceso de lectura")
        except Exception:
            logger.exception("Fallo reenviando el informe de sistema tras otorgar acceso")
