"""Deteccion sobre las conexiones que manda conn_watch.py del agente.

Tres eventos, sin capturar paquetes (el agente lee las conexiones activas
del sistema, con el proceso que las abrio):

- new_listener: un puerto que antes no escuchaba empieza a escuchar. El
  primer envio de cada host es la linea base y no genera eventos.
- service_outbound: una cuenta de servicio (www-data, nginx...) abre una
  conexion saliente a una IP publica en un puerto poco comun: la forma
  tipica de una reverse shell despues de explotar una web.
- malicious_connection: cualquier conexion saliente a una red de Spamhaus
  DROP.

La accion sugerida es terminar el proceso (si se conoce su PID): bloquear
la IP con fail2ban corta lo que entra, no lo que sale.
"""

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.host import Host
from app.models.security import HostListener
from app.schemas.logs import ConnectionsIn, ListenerIn, OutboundIn
from app.services import ids, netlists

# Salidas normales de cualquier servicio: DNS, NTP, HTTP(S), DNS sobre TLS.
COMMON_PORTS = {53, 80, 123, 443, 853}
# Un shell, un interprete o una herramienta de red escuchando o conectando
# sube la severidad: es lo que usa una bind/reverse shell.
SHELL_LIKE = {"bash", "sh", "dash", "zsh", "ksh", "nc", "ncat", "netcat", "socat", "python", "python3",
              "perl", "php", "ruby", "node", "telnet"}


def _shell_like(process: str | None) -> bool:
    name = (process or "").rsplit("/", 1)[-1].lower()
    return name in SHELL_LIKE or any(name.startswith(p) for p in ("python3.", "php"))


def _kill_action(pid: int | None, cmdline: str | None) -> str | None:
    return "kill_process" if pid and cmdline else None


async def _listeners(session: AsyncSession, host: Host, listeners: list[ListenerIn]) -> None:
    known = {(r.proto, r.port): r for r in (await session.execute(
        select(HostListener).where(HostListener.host_id == host.id))).scalars().all()}
    baseline = not known
    now = datetime.now(timezone.utc)
    seen: set[tuple[str, int]] = set()
    new: list[ListenerIn] = []
    for item in listeners:
        key = (item.proto, item.port)
        if key in seen:
            continue
        seen.add(key)
        row = known.get(key)
        if row:
            row.last_seen = now
            continue
        session.add(HostListener(host_id=host.id, proto=item.proto, port=item.port, address=item.address,
                                 user=item.user, process=item.process, first_seen=now, last_seen=now))
        if not baseline:
            new.append(item)
    await session.commit()

    for item in new:
        await ids.create_event(
            session, host, "new_listener", f"local:{item.proto}/{item.port}",
            {"proto": item.proto, "port": item.port, "address": item.address, "user": item.user,
             "process": item.process, "pid": item.pid, "cmdline": item.cmdline},
            severity="critical" if _shell_like(item.process) else "warning",
            suggested_action=_kill_action(item.pid, item.cmdline),
        )


async def _outbound(session: AsyncSession, host: Host, conn: OutboundIn) -> None:
    ip = netlists.parse_ip(conn.remote_ip)
    if not ip or not ip.is_global:
        return
    remote = str(ip)
    detail = {"proto": conn.proto, "remote_port": conn.remote_port, "local_port": conn.local_port,
              "user": conn.user, "process": conn.process, "pid": conn.pid, "cmdline": conn.cmdline}

    if netlists.threat_match(remote):
        kind, severity = "malicious_connection", "critical"
    elif conn.service_account and conn.remote_port not in COMMON_PORTS:
        kind, severity = "service_outbound", "critical" if _shell_like(conn.process) else "warning"
    else:
        return
    if await ids._open_event(session, host.id, kind, remote):
        return
    await ids.create_event(session, host, kind, remote, detail, severity=severity,
                           suggested_action=_kill_action(conn.pid, conn.cmdline))


async def process_connections(session: AsyncSession, host: Host, payload: ConnectionsIn) -> None:
    if payload.listeners is not None:
        await _listeners(session, host, payload.listeners)
    for conn in payload.outbound:
        await _outbound(session, host, conn)
