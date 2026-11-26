"""Lee nuevas lineas de logs de acceso (formato 'combined' de nginx/apache)
y las devuelve como entradas estructuradas para mandar al servidor.

Guarda el offset leido de cada archivo en un state file (JSON) para no
reprocesar todo el log en cada reinicio del agente, y para tolerar
rotacion de logs:
- si el inodo cambia (logrotate "create"), el archivo nuevo se lee desde
  el inicio;
- si el archivo quedo mas chico que lo ya leido (logrotate "copytruncate":
  mismo archivo, vaciado), tambien.
"""

import json
import os
import re
from datetime import datetime

STATE_PATH = os.environ.get(
    "SHINJI_SOC_LOG_STATE", os.path.join(os.path.dirname(os.path.abspath(__file__)), "log_state.json")
)
# Tope de entradas por lectura: tras horas con el agente detenido, el atraso
# se manda en varias partes y no en un solo envio enorme.
MAX_ENTRIES_PER_READ = 5000

_COMBINED_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+)[^"]*" '
    r'(?P<status>\d{3}) \S+ "[^"]*" "(?P<ua>[^"]*)"'
)
# Campos entre comillas despues del user-agent. Detras de Cloudflare o de un
# tunel, el log puede llevar al final la IP real del visitante, por ejemplo
# con nginx: log_format ... '"$http_user_agent" "$http_cf_connecting_ip"'.
_TRAILING_QUOTED_RE = re.compile(r'"([^"]*)"')


def is_access_line(line: str) -> bool:
    """La linea tiene formato combined (lo usa discovery para decidir que
    archivos son logs de acceso web)."""
    return bool(_COMBINED_RE.match(line.strip()))


def _load_state(state_path: str) -> dict:
    if os.path.exists(state_path):
        try:
            with open(state_path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return {}
    return {}


def _save_state(state_path: str, state: dict) -> None:
    with open(state_path, "w", encoding="utf-8") as fh:
        json.dump(state, fh)


def _parse_time(text: str) -> str | None:
    """'26/Nov/2026:10:00:00 -0300' -> '2026-11-26T10:00:00-03:00'.

    Con la zona: sin ella, el servidor tomaba la hora local como UTC y en un
    host con hora de Chile las peticiones quedaban 3 horas en el pasado,
    fuera de la ventana de conteo (la fuerza bruta web no se detectaba)."""
    for fmt in ("%d/%b/%Y:%H:%M:%S %z", "%d/%b/%Y:%H:%M:%S"):
        try:
            return datetime.strptime(text if "%z" in fmt else text.split(" ")[0], fmt).isoformat()
        except ValueError:
            continue
    return None


def _parse_line(line: str) -> dict | None:
    match = _COMBINED_RE.match(line)
    if not match:
        return None

    groups = match.groupdict()
    # El ultimo campo extra entre comillas, si hay: el servidor solo lo usa
    # cuando "ip" es la de un proxy de confianza (si no, cualquiera lo inventa).
    extra = [v for v in _TRAILING_QUOTED_RE.findall(line[match.end():]) if v and v != "-"]

    return {
        "ts": _parse_time(groups["time"]),
        "ip": groups["ip"],
        "forwarded_for": extra[-1][:200] if extra else None,
        "method": groups["method"],
        "path": groups["path"],
        "status_code": int(groups["status"]),
        "user_agent": groups["ua"],
    }


def read_new_entries(log_paths: list[str], max_entries: int = MAX_ENTRIES_PER_READ) -> list[dict]:
    """Lineas nuevas de cada archivo desde la ultima lectura. Si devuelve
    max_entries, quedan mas por leer: volver a llamar."""
    return tail(log_paths, STATE_PATH, _parse_line, max_entries)


def tail(log_paths: list[str], state_path: str, parse, max_entries: int) -> list[dict]:
    """Lee las lineas completas nuevas de cada archivo y devuelve las que
    parse() convierte (las que devuelven None se descartan). Lo usa tambien
    waf_watch, con su propio archivo de estado."""
    state = _load_state(state_path)
    entries: list[dict] = []

    for path in log_paths:
        if len(entries) >= max_entries:
            break
        try:
            st = os.stat(path)
        except OSError:
            continue
        saved = state.get(path)

        if saved is None:
            # Primera vez que vemos este archivo: arrancamos desde el final
            # para no mandar todo el historico de golpe.
            offset = st.st_size
        elif saved.get("inode") != st.st_ino or saved.get("offset", 0) > st.st_size:
            # Rotado (inodo nuevo) o truncado en el lugar: desde el inicio.
            offset = 0
        else:
            offset = saved.get("offset", 0)

        try:
            with open(path, "rb") as fh:
                fh.seek(offset)
                while len(entries) < max_entries:
                    raw = fh.readline()
                    if not raw:
                        break
                    if not raw.endswith(b"\n"):
                        # Linea a medio escribir: se lee completa la proxima vez.
                        fh.seek(-len(raw), os.SEEK_CUR)
                        break
                    parsed = parse(raw.decode("utf-8", errors="replace").strip())
                    if parsed:
                        entries.append(parsed)
                new_offset = fh.tell()
        except OSError:
            continue  # sin permiso o borrado justo ahora: los demas siguen

        state[path] = {"inode": st.st_ino, "offset": new_offset}

    _save_state(state_path, state)
    return entries
