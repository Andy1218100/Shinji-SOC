"""Intentos de inicio de sesion por SSH y en la interfaz web de Proxmox.

Fuente: el journal de systemd (journalctl). Proxmox VE 8 en adelante no
instala rsyslog, asi que no hay /var/log/auth.log
(https://pve.proxmox.com/wiki/Fail2ban). En hosts con rsyslog se usa
/var/log/auth.log. El usuario del agente esta en el grupo "adm", que puede
leer el journal del sistema.

Se parsea aca y al servidor solo va lo necesario (cuando, servicio,
resultado, usuario, IP): las lineas de log completas no salen del host.

Formatos (OpenSSH auth.c):
  "Failed password for [invalid user ]USER from IP port N ssh2"
  "Accepted publickey for USER from IP port N ssh2: ..."
  "Invalid user USER from IP port N"
("maximum authentication attempts exceeded" no se cuenta: sshd ya registra
un "Failed ..." por cada intento y se contaria dos veces.)
Proxmox (pvedaemon): "authentication failure; rhost=IP user=USER msg=..."
"""

import json
import logging
import os
import re
import shutil
import subprocess
from datetime import datetime, timezone

logger = logging.getLogger("auth_watch")

STATE_PATH = os.environ.get(
    "SHINJI_SOC_AUTH_STATE", os.path.join(os.path.dirname(os.path.abspath(__file__)), "auth_state.json")
)
AUTH_LOG = "/var/log/auth.log"
MAX_ENTRIES_PER_POLL = 5000

# sshd y, desde OpenSSH 9.8 (Debian 13), sshd-session para cada conexion;
# pvedaemon para el login de la interfaz web de Proxmox. Con "+" journalctl
# combina los grupos con OR.
JOURNAL_MATCHES = [
    "_SYSTEMD_UNIT=ssh.service", "+", "_SYSTEMD_UNIT=sshd.service", "+",
    "SYSLOG_IDENTIFIER=sshd", "+", "SYSLOG_IDENTIFIER=sshd-session", "+",
    "_SYSTEMD_UNIT=pvedaemon.service",
]

_SSH_RESULT = re.compile(r"\b(?P<result>Accepted|Failed) (?P<method>\S+) for (?:invalid user )?(?P<user>\S*) from (?P<ip>\S+) port \d+")
_SSH_INVALID = re.compile(r"\bInvalid user (?P<user>\S*) from (?P<ip>\S+) port \d+")
_PVE_FAILURE = re.compile(r"\bauthentication failure; rhost=(?P<ip>\S+) user=(?P<user>\S+) msg=")


def _clean_ip(ip: str) -> str:
    # pvedaemon escucha en IPv6 y loguea las IPv4 como ::ffff:1.2.3.4
    return ip[7:] if ip.lower().startswith("::ffff:") else ip


def parse_message(message: str, ts: datetime) -> dict | None:
    base = {"ts": ts.isoformat()}
    if m := _PVE_FAILURE.search(message):
        return {**base, "service": "pve", "outcome": "failed", "user": m["user"][:64], "ip": _clean_ip(m["ip"]), "method": "password"}
    if m := _SSH_RESULT.search(message):
        outcome = "accepted" if m["result"] == "Accepted" else "failed"
        return {**base, "service": "ssh", "outcome": outcome, "user": m["user"][:64], "ip": _clean_ip(m["ip"]), "method": m["method"][:32]}
    if m := _SSH_INVALID.search(message):
        return {**base, "service": "ssh", "outcome": "invalid_user", "user": m["user"][:64], "ip": _clean_ip(m["ip"]), "method": ""}
    return None


def _load_state() -> dict:
    try:
        with open(STATE_PATH, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def _save_state(state: dict) -> None:
    with open(STATE_PATH, "w", encoding="utf-8") as fh:
        json.dump(state, fh)


def detect_source() -> str | None:
    """"journal", la ruta de auth.log, o None si no hay de donde leer."""
    if shutil.which("journalctl"):
        try:
            r = subprocess.run(["journalctl", "-n", "1", "-q", "--no-pager", "_SYSTEMD_UNIT=systemd-journald.service"],
                               capture_output=True, text=True, timeout=15)
            # Sin permiso journalctl no falla: avisa que solo se ven los mensajes del propio usuario.
            denied = "insufficient permissions" in r.stderr or "not seeing messages" in r.stderr
            if r.returncode == 0 and not denied:
                return "journal"
        except (OSError, subprocess.TimeoutExpired):
            pass
    if os.access(AUTH_LOG, os.R_OK):
        return AUTH_LOG
    return None


def _message_text(value) -> str:
    # journalctl -o json manda MESSAGE como lista de bytes si no es UTF-8 valido.
    if isinstance(value, list):
        return bytes(v for v in value if isinstance(v, int)).decode("utf-8", "replace")
    return str(value or "")


def _read_journal(state: dict) -> list[dict]:
    args = ["journalctl", "-o", "json", "--no-pager", "-q"]
    cursor = state.get("journal_cursor")
    # Primera vez: solo lo de ahora en adelante, no todo el historico.
    args += ["--after-cursor", cursor] if cursor else ["--since", "-1min"]
    r = subprocess.run(args + JOURNAL_MATCHES, capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        raise RuntimeError(f"journalctl fallo: {r.stderr.strip()[:200]}")
    entries = []
    for line in r.stdout.splitlines()[-MAX_ENTRIES_PER_POLL:]:
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        state["journal_cursor"] = rec.get("__CURSOR", state.get("journal_cursor"))
        try:
            ts = datetime.fromtimestamp(int(rec["__REALTIME_TIMESTAMP"]) / 1_000_000, tz=timezone.utc)
        except (KeyError, ValueError):
            ts = datetime.now(timezone.utc)
        parsed = parse_message(_message_text(rec.get("MESSAGE")), ts)
        if parsed:
            entries.append(parsed)
    return entries


def _read_auth_log(state: dict) -> list[dict]:
    inode = os.stat(AUTH_LOG).st_ino
    saved = state.get("auth_log") or {}
    if not saved:
        offset = os.path.getsize(AUTH_LOG)
    elif saved.get("inode") != inode:
        offset = 0
    else:
        offset = saved.get("offset", 0)
    entries = []
    now = datetime.now(timezone.utc)
    with open(AUTH_LOG, "r", encoding="utf-8", errors="replace") as fh:
        fh.seek(offset)
        for line in fh:
            # Se lee cada 15 s: la hora de llegada alcanza y evita parsear
            # los distintos formatos de fecha de rsyslog.
            parsed = parse_message(line, now)
            if parsed:
                entries.append(parsed)
        state["auth_log"] = {"inode": inode, "offset": fh.tell()}
    return entries[-MAX_ENTRIES_PER_POLL:]


def read_new_entries(source: str) -> list[dict]:
    state = _load_state()
    entries = _read_journal(state) if source == "journal" else _read_auth_log(state)
    _save_state(state)
    return entries
