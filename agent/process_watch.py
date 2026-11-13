"""Vigila procesos de cuentas de servicio (www-data, nginx, etc.) buscando
ejecucion de binarios que normalmente no deberian correr bajo esas cuentas
(shells, intepretes, herramientas de red) -- indicador clasico de webshell
o ejecucion remota de comandos (RCE).

Es un heuristico por lista, no deteccion de comportamiento entrenada: va a
tener falsos positivos si la aplicacion legitimamente hace shell_exec/etc.
Por eso el servidor solo sugiere la accion, no la aplica solo.
"""

import os

import psutil

SUSPICIOUS_BINARIES = {
    "bash", "sh", "dash", "zsh", "ksh", "csh",
    "nc", "ncat", "netcat", "socat", "nmap",
    "wget", "curl",
    "python", "python2", "python3",
    "perl", "perl5",
    "php",
    "telnet",
}

_reported_pids: set[int] = set()


def _basename(cmdline: list[str]) -> str | None:
    if not cmdline:
        return None
    return os.path.basename(cmdline[0]).lower()


def scan(service_users: list[str]) -> list[dict]:
    if not service_users:
        return []

    users = set(service_users)
    anomalies: list[dict] = []
    live_pids: set[int] = set()

    for proc in psutil.process_iter(["pid", "username", "cmdline", "ppid"]):
        try:
            info = proc.info
            pid = info["pid"]
            live_pids.add(pid)

            if info["username"] not in users:
                continue

            binary = _basename(info["cmdline"])
            if binary not in SUSPICIOUS_BINARIES or pid in _reported_pids:
                continue

            parent_cmdline = None
            try:
                parent_cmdline = " ".join(psutil.Process(info["ppid"]).cmdline())
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

            anomalies.append(
                {
                    "user": info["username"],
                    "pid": pid,
                    "cmdline": " ".join(info["cmdline"]),
                    "parent_cmdline": parent_cmdline,
                }
            )
            _reported_pids.add(pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    _reported_pids.intersection_update(live_pids)
    return anomalies
