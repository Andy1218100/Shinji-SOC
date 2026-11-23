"""Conexiones activas del host, sin capturar paquetes.

Lee /proc/net/{tcp,tcp6,udp,udp6} (legibles por cualquier usuario: traen
direcciones, estado y el UID dueno de cada socket) y, para saber que
proceso abrio cada conexion, `ss -tunapH` via sudo (sudoers acotado a ese
comando exacto: solo lee). Sin sudo, todo funciona igual salvo el nombre
del proceso.

Manda al servidor:
- los puertos en escucha (lista completa, cuando cambia o cada 6 horas);
- las conexiones TCP salientes nuevas a IPs publicas.
El servidor decide que es sospechoso (services/conn_watch.py).

A diferencia de tcpdump, esto dice que proceso y que cuenta abrio cada
conexion; con HTTPS, tcpdump tampoco veria el contenido.
"""

import ipaddress
import os
import re
import subprocess
import time

try:
    import pwd
except ImportError:  # Windows (tests): sin nombres de usuario
    pwd = None

PROC_NET = "/proc/net"
SS_COMMAND = ["sudo", "-n", "/usr/bin/ss", "-tunapH"]
TCP_LISTEN, TCP_ESTABLISHED, UDP_UNCONNECTED = "0A", "01", "07"
# Puertos UDP efimeros (ip_local_port_range por defecto: 32768-60999): los
# abren los clientes (DNS, NTP) y cambian todo el tiempo; no son servicios.
UDP_EPHEMERAL_MIN = 32768
NOLOGIN_SHELLS = {"/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false", ""}
SYSTEM_UID_MAX = 999
EXCLUDED_USERS = {"root", "shinji-soc"}
LISTENERS_RESEND_SECONDS = 6 * 3600
OUTBOUND_MEMORY_SECONDS = 3600

_USERS_RE = re.compile(r'\("([^"]+)",pid=(\d+)')


def _hex_ip(text: str) -> str:
    """Direccion de /proc/net: IPv4 son 4 bytes en orden de la maquina
    (little-endian); IPv6, cuatro palabras de 4 bytes, cada una igual."""
    raw = bytes.fromhex(text)
    if len(raw) == 4:
        ip = ipaddress.ip_address(raw[::-1])
    else:
        ip = ipaddress.ip_address(b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4)))
        if ip.ipv4_mapped:
            ip = ip.ipv4_mapped
    return str(ip)


def parse_proc_net(text: str, proto: str) -> list[dict]:
    sockets = []
    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 10:
            continue
        try:
            local_ip, local_port = fields[1].split(":")
            remote_ip, remote_port = fields[2].split(":")
            sockets.append({
                "proto": proto,
                "local_ip": _hex_ip(local_ip), "local_port": int(local_port, 16),
                "remote_ip": _hex_ip(remote_ip), "remote_port": int(remote_port, 16),
                "state": fields[3], "uid": int(fields[7]),
            })
        except (ValueError, IndexError):
            continue
    return sockets


def _split_addr(text: str) -> tuple[str, str]:
    host, _, port = text.rpartition(":")
    host = host.strip("[]").split("%")[0]
    try:
        ip = ipaddress.ip_address(host)
        if ip.version == 6 and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        host = str(ip)
    except ValueError:
        pass  # "*" en las direcciones remotas de los que escuchan
    return host, port


def parse_ss(text: str) -> dict:
    """{(proto, ip_local, puerto_local, ip_remota, puerto_remoto): (proceso, pid)}"""
    owners = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 6:
            continue
        match = _USERS_RE.search(line)
        if not match:
            continue
        local_ip, local_port = _split_addr(fields[4])
        remote_ip, remote_port = _split_addr(fields[5])
        owners[(fields[0], local_ip, local_port, remote_ip, remote_port)] = (match.group(1), int(match.group(2)))
    return owners


def _read(path: str) -> str:
    try:
        with open(path, encoding="ascii", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def _ss_owners() -> dict:
    try:
        out = subprocess.run(SS_COMMAND, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return {}
    return parse_ss(out.stdout) if out.returncode == 0 else {}


def _cmdline(pid: int | None) -> str | None:
    if not pid:
        return None
    raw = _read(f"/proc/{pid}/cmdline")
    return raw.replace("\0", " ").strip()[:1000] or None


_user_cache: dict[int, tuple[str | None, bool]] = {}


def _user(uid: int) -> tuple[str | None, bool]:
    """(nombre, es_cuenta_de_servicio) con la misma regla que discovery.py."""
    if uid not in _user_cache:
        name, service = None, False
        if pwd is not None:
            try:
                entry = pwd.getpwuid(uid)
                name = entry.pw_name
                service = name not in EXCLUDED_USERS and (entry.pw_shell in NOLOGIN_SHELLS or uid < SYSTEM_UID_MAX)
            except KeyError:
                pass
        _user_cache[uid] = (name, service)
    return _user_cache[uid]


def snapshot(proc_net: str = PROC_NET, owners: dict | None = None) -> tuple[list[dict], list[dict]]:
    """(puertos en escucha, conexiones TCP salientes a IPs publicas)."""
    sockets = []
    for name, proto in (("tcp", "tcp"), ("tcp6", "tcp"), ("udp", "udp"), ("udp6", "udp")):
        sockets += parse_proc_net(_read(os.path.join(proc_net, name)), proto)
    if owners is None:
        owners = _ss_owners()

    # Los que escuchan aparecen en ss con el remoto "0.0.0.0:*", "[::]:*" o
    # "*:*": se buscan solo por protocolo, direccion y puerto local.
    listen_owners = {(k[0], k[1], k[2]): v for k, v in owners.items() if k[4] == "*"}

    def owner(s: dict, listening: bool) -> tuple[str | None, int | None]:
        port = str(s["local_port"])
        if listening:
            for local_ip in (s["local_ip"], "*", "0.0.0.0", "::"):
                hit = listen_owners.get((s["proto"], local_ip, port))
                if hit:
                    return hit
            return None, None
        return owners.get((s["proto"], s["local_ip"], port, s["remote_ip"], str(s["remote_port"])), (None, None))

    listeners, outbound = [], []
    listening_tcp_ports = {s["local_port"] for s in sockets if s["proto"] == "tcp" and s["state"] == TCP_LISTEN}
    for s in sockets:
        is_listener = (s["proto"] == "tcp" and s["state"] == TCP_LISTEN) or (
            s["proto"] == "udp" and s["state"] == UDP_UNCONNECTED and s["local_port"] < UDP_EPHEMERAL_MIN)
        if is_listener:
            user, _ = _user(s["uid"])
            process, pid = owner(s, True)
            listeners.append({"proto": s["proto"], "address": s["local_ip"], "port": s["local_port"],
                              "user": user, "process": process, "pid": pid, "cmdline": _cmdline(pid)})
            continue
        if s["proto"] != "tcp" or s["state"] != TCP_ESTABLISHED or s["local_port"] in listening_tcp_ports:
            continue  # solo salientes: las que llegan a un puerto propio en escucha son entrantes
        try:
            if not ipaddress.ip_address(s["remote_ip"]).is_global:
                continue
        except ValueError:
            continue
        user, service = _user(s["uid"])
        process, pid = owner(s, False)
        outbound.append({"proto": "tcp", "local_port": s["local_port"], "remote_ip": s["remote_ip"],
                         "remote_port": s["remote_port"], "user": user, "service_account": service,
                         "process": process, "pid": pid, "cmdline": _cmdline(pid)})
    return listeners, outbound


class Tracker:
    """Decide que mandar en cada vuelta: los puertos en escucha si cambiaron
    (o cada 6 h), y solo las conexiones salientes no vistas en la ultima hora."""

    def __init__(self) -> None:
        self._listeners_key: frozenset | None = None
        self._listeners_sent_at = 0.0
        self._seen: dict[tuple, float] = {}

    def payload(self, listeners: list[dict], outbound: list[dict], now: float | None = None) -> dict | None:
        now = time.time() if now is None else now
        body: dict = {"listeners": None, "outbound": []}
        key = frozenset((item["proto"], item["port"]) for item in listeners)
        if key != self._listeners_key or now - self._listeners_sent_at > LISTENERS_RESEND_SECONDS:
            body["listeners"] = listeners
            self._listeners_key, self._listeners_sent_at = key, now
        self._seen = {k: t for k, t in self._seen.items() if now - t < OUTBOUND_MEMORY_SECONDS}
        for conn in outbound:
            k = (conn["user"], conn["remote_ip"], conn["remote_port"], conn["process"])
            if k not in self._seen:
                self._seen[k] = now
                body["outbound"].append(conn)
        if body["listeners"] is None and not body["outbound"]:
            return None
        return body
