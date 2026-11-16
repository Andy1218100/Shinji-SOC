"""Simulacion de ataques para probar el mapa y el IDS (solo para pruebas).

Crea un host ficticio, "Simulacion de ataques", y le manda por la misma API
que usa el agente (logs web y logins fallidos) oleadas de ataques desde IPs
publicas de otros paises. El servidor los procesa igual que los reales: el
IDS abre eventos, GeoIP los ubica, el mapa los dibuja y la IA los resume.

No sale trafico hacia esas IPs: se eligen al azar entre las direcciones
publicas que la base GeoLite2 ubica en algun pais, y solo se escriben como
origen en lo que recibe el servidor. Los eventos van al host ficticio, que
no tiene agente: aprobar un bloqueo deja el comando pendiente para siempre y
no toca el fail2ban de ningun servidor real.

El mapa solo muestra los ultimos 10 minutos, por eso corre en bucle. Cada
oleada borra los datos del host ficticio con mas de --keep-minutes, asi no
se acumulan eventos abiertos.

Uso (desde la carpeta del proyecto):
  docker compose exec -d server sh -c "python -m scripts.simulate_attack >> /tmp/attack-sim.log 2>&1"
                                                                             en bucle, en segundo plano (log en /tmp/attack-sim.log)
  docker compose exec server python -m scripts.simulate_attack --once       una sola oleada
  docker compose exec server python -m scripts.simulate_attack --stop       detiene el bucle
  docker compose exec server python -m scripts.simulate_attack --clean      detiene y borra el host y sus datos
El bucle se corta tambien si se reinicia o recrea el contenedor del servidor.
"""

import argparse
import asyncio
import ipaddress
import logging
import os
import random
import secrets
import signal
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
from sqlalchemy import delete, select

from app.core.config import settings
from app.core.db import SessionLocal
from app.models.host import Host
from app.models.security import AuthAttempt, BlockedIP, Command, IngestedRequest, SecurityEvent
from app.services import geoip

HOST_NAME = "Simulacion de ataques"
API = "http://127.0.0.1:8000/api/v1"
PID_FILE = Path("/tmp/prox-secure-attack-sim.pid")
HOME_COUNTRY = "Chile"  # el host ficticio se ubica aca, para que los arcos tengan destino

SCAN_PATHS = ["/.env", "/wp-login.php", "/.git/config", "/phpmyadmin/", "/xmlrpc.php", "/admin/config.php",
              "/cgi-bin/luci", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "/boaform/admin/formLogin"]
USER_AGENTS = ["Mozilla/5.0 zgrab/0.x", "python-requests/2.31.0", "Go-http-client/1.1", "curl/8.5.0",
               "Mozilla/5.0 (compatible; Nmap Scripting Engine)"]
SSH_USERS = ["root", "admin", "ubuntu", "test", "oracle", "postgres", "git", "pi", "support"]

log = logging.getLogger("simulate_attack")


def build_pool(size: int = 48, per_country: int = 2) -> tuple[list[tuple[str, str]], str | None]:
    """IPs publicas al azar que GeoLite2 ubica, maximo `per_country` por
    pais. Devuelve [(ip, pais)] y una IP de HOME_COUNTRY para el host."""
    if not geoip.is_configured():
        sys.exit("No hay base GeoIP: sin ella los ataques no tienen ubicacion. Descargala en Configuracion > Mapa de ataques.")
    rng = random.SystemRandom()
    pool, counts, home = [], {}, None
    for _ in range(60000):
        ip = ipaddress.IPv4Address(rng.getrandbits(32))
        if not ip.is_global or ip.is_multicast:
            continue
        geo = geoip.lookup(str(ip))
        if geo.lat is None or geo.lon is None or not geo.country:
            continue
        if geo.country == HOME_COUNTRY:
            home = home or str(ip)
            continue
        if counts.get(geo.country, 0) >= per_country:
            continue
        counts[geo.country] = counts.get(geo.country, 0) + 1
        pool.append((str(ip), geo.country))
        if len(pool) >= size and home:
            break
    return pool, home


async def ensure_host(home_ip: str | None) -> Host:
    async with SessionLocal() as session:
        host = (await session.execute(select(Host).where(Host.name == HOST_NAME))).scalar_one_or_none()
        if host is None:
            host = Host(name=HOST_NAME, hostname="simulacion.invalid", os="Simulacion (sin agente)",
                        api_key=secrets.token_urlsafe(32))
            session.add(host)
        if home_ip:
            host.ip_address = home_ip
        await session.commit()
        await session.refresh(host)
        return host


async def purge(host_id, older_than: timedelta | None) -> None:
    """Borra datos del host ficticio (todos, o los mas viejos que older_than)."""
    cutoff = datetime.now(timezone.utc) - older_than if older_than else None
    async with SessionLocal() as session:
        for model, ts in ((SecurityEvent, SecurityEvent.created_at), (IngestedRequest, IngestedRequest.ts),
                          (AuthAttempt, AuthAttempt.ts)):
            q = delete(model).where(model.host_id == host_id)
            if cutoff is not None:
                q = q.where(ts < cutoff)
            await session.execute(q)
        # Bloqueos aprobados sobre el host ficticio: nunca se ejecutan, se limpian siempre.
        await session.execute(delete(Command).where(Command.host_id == host_id))
        await session.execute(delete(BlockedIP).where(BlockedIP.host_id == host_id))
        await session.commit()


async def busy_ips(host_id) -> set[str]:
    async with SessionLocal() as session:
        rows = await session.execute(select(SecurityEvent.source_ip).where(
            SecurityEvent.host_id == host_id, SecurityEvent.status == "open"))
        return {r[0] for r in rows}


def attack_payload(kind: str, ip: str) -> tuple[str, dict]:
    now = datetime.now(timezone.utc)
    if kind == "path_scan":
        paths = random.sample(SCAN_PATHS, 4)
        ua = random.choice(USER_AGENTS)
        return "logs/ingest", {"entries": [
            {"ts": (now - timedelta(seconds=4 - i)).isoformat(), "ip": ip, "method": "GET", "path": p,
             "status_code": 404, "user_agent": ua} for i, p in enumerate(paths)]}
    if kind == "brute_force":
        n = settings.ids_requests_threshold + 5
        return "logs/ingest", {"entries": [
            {"ts": (now - timedelta(milliseconds=200 * (n - i))).isoformat(), "ip": ip, "method": "POST",
             "path": "/login", "status_code": 401, "user_agent": "python-requests/2.31.0"} for i in range(n)]}
    service = "pve" if kind == "pve_brute_force" else "ssh"
    n = settings.ssh_fail_threshold + random.randint(1, 8)
    users = random.sample(SSH_USERS, random.randint(1, 4))
    if service == "pve":
        users = [f"{u}@pam" for u in users]
    return "auth-events/ingest", {"entries": [
        {"ts": (now - timedelta(seconds=3 * (n - i))).isoformat(), "service": service, "outcome": "failed",
         "user": random.choice(users), "ip": ip, "method": "password"} for i in range(n)]}


KINDS = ["path_scan"] * 4 + ["ssh_brute_force"] * 3 + ["brute_force", "pve_brute_force"]


async def wave(client: httpx.AsyncClient, host: Host, pool: list[tuple[str, str]], keep: timedelta) -> None:
    await purge(host.id, keep)
    busy = await busy_ips(host.id)
    free = [p for p in pool if p[0] not in busy]
    for ip, country in random.sample(free, min(len(free), random.randint(1, 3))):
        kind = random.choice(KINDS)
        path, body = attack_payload(kind, ip)
        resp = await client.post(f"{API}/{path}", json=body, headers={"X-API-Key": host.api_key})
        log.info("%s desde %s (%s): HTTP %s", kind, ip, country, resp.status_code)


def stop_running() -> bool:
    try:
        pid = int(PID_FILE.read_text())
        os.kill(pid, signal.SIGTERM)
    except (OSError, ValueError):
        PID_FILE.unlink(missing_ok=True)
        return False
    PID_FILE.unlink(missing_ok=True)
    return True


async def main() -> None:
    parser = argparse.ArgumentParser(description="Simulacion de ataques para probar el mapa")
    parser.add_argument("--once", action="store_true", help="una sola oleada")
    parser.add_argument("--stop", action="store_true", help="detiene el bucle")
    parser.add_argument("--clean", action="store_true", help="detiene el bucle y borra el host ficticio y sus datos")
    parser.add_argument("--interval", type=int, default=180, help="segundos entre oleadas (por defecto 180)")
    parser.add_argument("--keep-minutes", type=int, default=30, help="minutos que se conservan los datos simulados")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)

    if args.stop or args.clean:
        print("Bucle detenido." if stop_running() else "No habia un bucle corriendo.")
        if args.clean:
            async with SessionLocal() as session:
                host = (await session.execute(select(Host).where(Host.name == HOST_NAME))).scalar_one_or_none()
            if host is None:
                print("No hay host de simulacion.")
                return
            await purge(host.id, None)
            async with SessionLocal() as session:
                await session.delete(await session.get(Host, host.id))
                await session.commit()
            print(f'Borrado el host "{HOST_NAME}" y todos sus datos.')
        return

    pool, home = build_pool()
    countries = sorted({c for _, c in pool})
    log.info("%d IPs de %d paises; host ficticio ubicado en %s", len(pool), len(countries),
             HOME_COUNTRY if home else "ninguna parte (sin IP de ese pais)")
    host = await ensure_host(home)
    keep = timedelta(minutes=args.keep_minutes)

    async with httpx.AsyncClient(timeout=60) as client:
        if args.once:
            await wave(client, host, pool, keep)
            return
        if PID_FILE.exists() and stop_running():
            log.info("Habia otro bucle corriendo: lo detuve")
        PID_FILE.write_text(str(os.getpid()))
        try:
            while True:
                try:
                    await wave(client, host, pool, keep)
                except Exception:  # el servidor se reinicio (reload) o la base no respondio
                    log.exception("Oleada fallida; se reintenta en la proxima")
                await asyncio.sleep(args.interval)
        finally:
            if PID_FILE.exists() and PID_FILE.read_text() == str(os.getpid()):
                PID_FILE.unlink()


if __name__ == "__main__":
    asyncio.run(main())
