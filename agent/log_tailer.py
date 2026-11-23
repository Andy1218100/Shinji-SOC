"""Lee nuevas lineas de logs de acceso (formato 'combined' de nginx/apache)
y las devuelve como entradas estructuradas para mandar al servidor.

Guarda el offset leido de cada archivo en un state file (JSON) para no
reprocesar todo el log en cada reinicio del agente, y para tolerar rotacion
de logs (si el inodo cambia, se asume rotacion y se arranca desde el inicio
del archivo nuevo).
"""

import json
import os
import re
from datetime import datetime

STATE_PATH = os.environ.get(
    "SHINJI_SOC_LOG_STATE", os.path.join(os.path.dirname(os.path.abspath(__file__)), "log_state.json")
)

_COMBINED_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+)[^"]*" '
    r'(?P<status>\d{3}) \S+ "[^"]*" "(?P<ua>[^"]*)"'
)
# Campos entre comillas despues del user-agent. Detras de Cloudflare o de un
# tunel, el log puede llevar al final la IP real del visitante, por ejemplo
# con nginx: log_format ... '"$http_user_agent" "$http_cf_connecting_ip"'.
_TRAILING_QUOTED_RE = re.compile(r'"([^"]*)"')


def _load_state() -> dict:
    if os.path.exists(STATE_PATH):
        with open(STATE_PATH, "r", encoding="utf-8") as fh:
            return json.load(fh)
    return {}


def _save_state(state: dict) -> None:
    with open(STATE_PATH, "w", encoding="utf-8") as fh:
        json.dump(state, fh)


def _parse_line(line: str) -> dict | None:
    match = _COMBINED_RE.match(line)
    if not match:
        return None

    groups = match.groupdict()
    try:
        ts = datetime.strptime(groups["time"].split(" ")[0], "%d/%b/%Y:%H:%M:%S")
    except ValueError:
        ts = None

    # El ultimo campo extra entre comillas, si hay: el servidor solo lo usa
    # cuando "ip" es la de un proxy de confianza (si no, cualquiera lo inventa).
    extra = [v for v in _TRAILING_QUOTED_RE.findall(line[match.end():]) if v and v != "-"]

    return {
        "ts": ts.isoformat() if ts else None,
        "ip": groups["ip"],
        "forwarded_for": extra[-1][:200] if extra else None,
        "method": groups["method"],
        "path": groups["path"],
        "status_code": int(groups["status"]),
        "user_agent": groups["ua"],
    }


def read_new_entries(log_paths: list[str]) -> list[dict]:
    state = _load_state()
    entries: list[dict] = []

    for path in log_paths:
        if not os.path.exists(path):
            continue

        inode = os.stat(path).st_ino
        saved = state.get(path)

        if saved is None:
            # Primera vez que vemos este archivo: arrancamos desde el final
            # para no mandar todo el historico de golpe.
            offset = os.path.getsize(path)
        elif saved.get("inode") != inode:
            # El inodo cambio: el log roto, el archivo nuevo empieza en 0.
            offset = 0
        else:
            offset = saved.get("offset", 0)

        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            fh.seek(offset)
            for line in fh:
                parsed = _parse_line(line.strip())
                if parsed:
                    entries.append(parsed)
            new_offset = fh.tell()

        state[path] = {"inode": inode, "offset": new_offset}

    _save_state(state)
    return entries
