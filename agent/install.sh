#!/usr/bin/env bash
# Instala el agente de Prox Secure en un servidor Linux (Debian/Ubuntu).
# Autocontenido: alcanza con este archivo, no hace falta nada mas de este
# repo en el servidor. Generado por _build_install.sh -- no editar a mano
# los archivos embebidos de aca abajo, editar el fuente real en agent/ y
# volver a generar.
# Uso: sudo bash install.sh <server_url> <api_key>
set -euo pipefail

SERVER_URL="${1:?Falta server_url, ej: http://10.0.0.5:8000}"
API_KEY="${2:?Falta api_key del host (se genera al crear el host en el servidor)}"
INSTALL_DIR="/opt/prox-secure-agent"

if [[ $EUID -ne 0 ]]; then
  echo "Este script debe ejecutarse como root (sudo)." >&2
  exit 1
fi

# Dependencias del sistema. Se instalan siempre (apt no reinstala lo que
# ya esta, es rapido) en vez de detectar que falta uno por uno -- asi se
# evita el problema clasico de Debian donde python3 esta pero el modulo
# venv/pip no, porque van en paquetes separados (python3-venv, python3-pip).
# "sudo" se incluye a proposito: en hosts tipo hipervisor (Proxmox VE y
# similares, donde todo se maneja como root directamente) suele no venir
# instalado, y sin el no existe "visudo" (lo necesitamos mas abajo para
# validar el sudoers acotado del agente) ni funciona el bloqueo/kill
# aprobado desde el dashboard (commands.py invoca "sudo" en tiempo real).
echo "Instalando dependencias del sistema (python3, venv, pip, sudo, fail2ban)..."
apt-get update -y
apt-get install -y python3 python3-venv python3-pip sudo fail2ban

id -u prox-secure &>/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin prox-secure
# Grupo "adm": en Debian/Ubuntu es el dueno de lectura de /var/log/nginx,
# /var/log/apache2, etc. Sin esto, los logs que el agente autodetecta
# (ver discovery.py) existen pero no los puede leer.
usermod -aG adm prox-secure

mkdir -p "$INSTALL_DIR"

echo "Escribiendo los archivos del agente en $INSTALL_DIR..."
mkdir -p "$(dirname "$INSTALL_DIR/commands.py")"
cat > "$INSTALL_DIR/commands.py" <<'PROXSECURE_EMBED_1_EOF'
"""Ejecuta comandos aprobados por el administrador desde el panel
(bloquear IP via fail2ban, terminar un proceso) usando los permisos
acotados definidos en sudoers/prox-secure-agent. El agente en si corre
sin privilegios; solo esas dos acciones puntuales usan sudo.
"""

import logging
import os
import subprocess

import httpx

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

    return False, f"accion desconocida: {action}"


async def poll_and_execute(client: httpx.AsyncClient, base_url: str, headers: dict, fail2ban_jail: str) -> None:
    resp = await client.get(f"{base_url}/api/v1/commands/pending", headers=headers)
    resp.raise_for_status()
    commands = resp.json()

    for command in commands:
        ok, output = execute(command, fail2ban_jail)
        logger.info("Comando %s (%s): %s -> %s", command["id"], command["action"], ok, output)
        await client.post(
            f"{base_url}/api/v1/commands/{command['id']}/result",
            headers=headers,
            json={"status": "done" if ok else "failed", "result": output},
        )
PROXSECURE_EMBED_1_EOF

mkdir -p "$(dirname "$INSTALL_DIR/config.py")"
cat > "$INSTALL_DIR/config.py" <<'PROXSECURE_EMBED_2_EOF'
import os
import sys

import yaml

CONFIG_PATH = os.environ.get(
    "PROX_SECURE_CONFIG", os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.yaml")
)

_DEFAULTS = {
    "server_url": "http://localhost:8000",
    "api_key": "",
    "metrics_interval_seconds": 15,
    "log_paths": [],
    "process_watch": {"interval_seconds": 10, "service_users": []},
    "command_poll_interval_seconds": 10,
    "fail2ban_jail": "proxsecure",
    "inventory_interval_seconds": 86400,
    "discovery_interval_seconds": 86400,
}


def load() -> dict:
    config = dict(_DEFAULTS)

    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
            config.update(yaml.safe_load(fh) or {})

    config["server_url"] = os.environ.get("PROX_SECURE_SERVER_URL", config["server_url"])
    config["api_key"] = os.environ.get("PROX_SECURE_API_KEY", config["api_key"])

    if not config["api_key"]:
        print("Falta api_key. Define config.yaml o PROX_SECURE_API_KEY.", file=sys.stderr)
        sys.exit(1)

    return config
PROXSECURE_EMBED_2_EOF

mkdir -p "$(dirname "$INSTALL_DIR/discovery.py")"
cat > "$INSTALL_DIR/discovery.py" <<'PROXSECURE_EMBED_3_EOF'
"""Descubrimiento del sistema: que es este host, que corre, que puertos
tiene abiertos, y que logs/cuentas de servicio tiene sentido vigilar en
*este* host en particular -- en vez de depender de que el admin edite
log_paths/service_users a mano en config.yaml para cada maquina.

Corre sin privilegios (igual que el resto del agente): usa /etc/os-release,
psutil (que ya se usa sin root en process_watch.py) y chequeos de archivos
conocidos. Si algo no se puede determinar, se devuelve vacio/None en vez de
fallar -- el resto del agente ya esta hecho para degradar con gracia.
"""

import logging
import os
import platform
import pwd

import psutil

logger = logging.getLogger("discovery")

# proceso -> etiqueta legible. Basta con que el nombre del binario
# contenga la clave (ej. "mysqld" matchea aunque el binario real sea
# /usr/sbin/mysqld).
KNOWN_SERVICE_PROCESSES = {
    "nginx": "nginx",
    "apache2": "apache",
    "httpd": "apache",
    "postgres": "postgresql",
    "mysqld": "mysql",
    "mariadbd": "mysql",
    "redis-server": "redis",
    "mongod": "mongodb",
    "dockerd": "docker",
    "sshd": "ssh",
}

# servidor web detectado por binario -> donde busca su log de acceso
# formato "combined". Si el admin ya definio log_paths a mano, estos
# valores autodetectados ni se usan (ver main.py).
WEB_SERVER_LOG_CANDIDATES = {
    "nginx": ["/var/log/nginx/access.log"],
    "apache2": ["/var/log/apache2/access.log"],
    "httpd": ["/var/log/httpd/access_log"],
}

# Cuentas que NO se vigilan aunque cumplan "cuenta de sistema con proceso
# activo": el usuario del propio agente (para no terminar vigilandose a
# si mismo -- cada comando aprobado se ejecuta via "sudo ...", que es
# justo el patron que busca process_watch.py) y root (root ejecutando lo
# que sea no es una anomalia, es el superusuario).
WATCH_EXCLUDED_USERS = {"root", "prox-secure"}
NOLOGIN_SHELLS = {"/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false", ""}
SYSTEM_UID_MAX = 999  # convencion Debian/Ubuntu: UIDs de cuentas de sistema son < 1000

# Busqueda de logs mas alla de nginx/apache: cualquier archivo cuyo
# nombre tenga ".log"/".logs", o que viva dentro de una carpeta llamada
# justo "log"/"logs", buscando solo en las rutas donde de verdad suele
# haber logs de aplicaciones (nunca toda la raiz "/": ahi estan /proc,
# /sys y montajes que no tiene sentido recorrer y pueden ser enormes).
LOG_SCAN_ROOTS = ("/var/log", "/opt", "/srv", "/home", "/root")
LOG_FILENAME_MARKERS = (".log", ".logs")
LOG_DIRNAME_MARKER = "log"  # substring, no igualdad exacta: cubre "logs", "AMP_Logs", "mylogs", etc.
# 10, no 6: algunas apps (ej. AMP, que guarda todo bajo un directorio oculto
# tipo .ampdata/instances/<id>/<juego>/<carpeta-del-juego>/logs/...) anidan
# bastante.
LOG_SCAN_MAX_DEPTH = 10
# Medido en un servidor real (Proxmox + AMP con varias instancias de
# juego + Podman): /home solo tenia 112.381 carpetas, con contenido de
# verdad (instalaciones completas de juegos) ademas de lo que ya se filtra
# de Podman. os.walk mide ~49.000 carpetas/seg en este tipo de arbol, asi
# que hasta ese numero real se recorre en un par de segundos -- costo
# unico al arrancar el agente (o 1 vez al dia), nunca en un loop caliente.
# Por raiz, no total: si se dividiera un total entre las 5 rutas, una
# sola con mucho contenido real (como paso con /home) se quedaria corta.
# Peor caso si las 5 fueran igual de grandes: 5 x 200.000 ~ 20s a la
# velocidad medida arriba -- aceptable para algo que corre 1 vez al dia.
LOG_SCAN_MAX_DIRS_PER_ROOT = 200_000
LOG_SCAN_MAX_RESULTS = 100
# Carpetas que nunca tiene sentido recorrer buscando logs de aplicacion:
# son potencialmente enormes y lo unico que van a aportar es ruido
# repetido. El caso real que motivo esto: el storage de imagenes de
# podman/docker bajo .local/share/containers/storage/overlay/<hash>/diff
# duplica un filesystem *completo* (con su propio /var/log adentro) por
# cada capa de cada imagen bajada -- en un host con varias imagenes esto
# son miles de carpetas, y alcanzaban a agotar el presupuesto de arriba
# antes de llegar siquiera a los logs reales de la app (visto en un
# servidor real con AMP: nunca llegaba a .ampdata).
LOG_SCAN_SKIP_MARKERS = ("/containers/storage/", "/.cache/", "/node_modules/", "/.git/", "/__pycache__/")


def detect_os() -> dict:
    info = {}
    try:
        with open("/etc/os-release", "r", encoding="utf-8") as fh:
            for line in fh:
                if "=" in line:
                    key, _, value = line.strip().partition("=")
                    info[key] = value.strip('"')
    except OSError:
        pass

    return {
        "os_name": info.get("PRETTY_NAME") or info.get("NAME"),
        "os_version_id": info.get("VERSION_ID"),
        "kernel": platform.release(),
    }


def detect_hardware() -> dict:
    hardware = {"cpu_count": None, "mem_total_mb": None, "disk_total_gb": None}
    try:
        hardware["cpu_count"] = psutil.cpu_count(logical=True)
    except Exception:
        logger.exception("No se pudo leer cpu_count")
    try:
        hardware["mem_total_mb"] = round(psutil.virtual_memory().total / (1024 * 1024), 1)
    except Exception:
        logger.exception("No se pudo leer memoria total")
    try:
        hardware["disk_total_gb"] = round(psutil.disk_usage("/").total / (1024 ** 3), 1)
    except Exception:
        logger.exception("No se pudo leer disco total")
    return hardware


def detect_running_services() -> list[str]:
    found: set[str] = set()
    try:
        for proc in psutil.process_iter(["name"]):
            name = (proc.info.get("name") or "").lower()
            for proc_name, label in KNOWN_SERVICE_PROCESSES.items():
                if proc_name in name:
                    found.add(label)
    except Exception:
        logger.exception("No se pudo listar procesos para detectar servicios")
    return sorted(found)


def detect_listening_ports() -> list[dict]:
    ports: list[dict] = []
    seen: set[int] = set()
    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.status != psutil.CONN_LISTEN or not conn.laddr or conn.laddr.port in seen:
                continue
            seen.add(conn.laddr.port)
            process_name = None
            if conn.pid:
                try:
                    process_name = psutil.Process(conn.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            ports.append({"port": conn.laddr.port, "process": process_name})
    except Exception:
        logger.exception("No se pudo leer puertos en escucha")
    return sorted(ports, key=lambda p: p["port"])


def _looks_like_log(filename: str) -> bool:
    lowered = filename.lower()
    return any(marker in lowered for marker in LOG_FILENAME_MARKERS)


def _should_skip_dir(dirpath: str) -> bool:
    normalized = dirpath.replace("\\", "/") + "/"
    return any(marker in normalized for marker in LOG_SCAN_SKIP_MARKERS)


def _prioritize_log_dirs(dirnames: list[str]) -> None:
    """Reordena in-place para que, si una carpeta tiene una subcarpeta que
    suena a logs junto con otras que no, se visite primero la que suena a
    logs. No alcanza para decidir entre dos carpetas genericas (ninguna
    tiene "log" en el nombre) -- para eso esta _should_skip_dir, que corta
    de raiz los arboles que se sabe de antemano que son ruido."""
    dirnames.sort(key=lambda d: 0 if LOG_DIRNAME_MARKER in d.lower() else 1)


def _scan_for_log_files() -> tuple[list[str], list[str]]:
    """Busqueda acotada (no toda la raiz, con tope de carpetas y resultados)
    de cualquier archivo que parezca un log, mas alla de los paths fijos de
    nginx/apache. Que un archivo aparezca aca no garantiza que sea un log
    de acceso HTTP util para el IDS -- el parser de logs ya ignora en
    silencio cualquier linea que no tenga el formato esperado, asi que el
    costo de vigilar uno que no sirve es nomas un poco de I/O, nunca un
    error. Se prioriza mostrar todo lo que puede ser relevante (lo pidio
    el usuario explicitamente) por sobre ser quirurgico.

    Devuelve (encontrados, carpetas_sin_permiso_de_entrar). Esto ultimo
    importa para apps que guardan todo bajo un directorio con permisos
    cerrados (ej. 0700, solo el dueno) -- tipicamente un directorio oculto
    como ".ampdata" en instalaciones de AMP. Si el agente no puede ni
    listar esa carpeta, lo de adentro queda invisible para el
    descubrimiento (no es que lo encuentre y no lo pueda leer: direc-
    tamente no lo ve), y eso hay que poder distinguirlo y mostrarlo.
    """
    found: set[str] = set()
    denied_dirs: set[str] = set()

    def _on_error(exc: OSError) -> None:
        if exc.filename:
            denied_dirs.add(exc.filename)

    for root in LOG_SCAN_ROOTS:
        if len(found) >= LOG_SCAN_MAX_RESULTS:
            break
        if not os.path.isdir(root):
            continue

        visited_in_root = 0
        base_depth = root.rstrip(os.sep).count(os.sep)
        try:
            walker = os.walk(root, onerror=_on_error)
            for dirpath, dirnames, filenames in walker:
                visited_in_root += 1
                depth = dirpath.rstrip(os.sep).count(os.sep) - base_depth

                if visited_in_root >= LOG_SCAN_MAX_DIRS_PER_ROOT or len(found) >= LOG_SCAN_MAX_RESULTS:
                    dirnames[:] = []
                    break
                if _should_skip_dir(dirpath):
                    dirnames[:] = []
                    continue
                if depth >= LOG_SCAN_MAX_DEPTH:
                    dirnames[:] = []  # no seguir bajando en este subarbol
                _prioritize_log_dirs(dirnames)

                in_log_dir = LOG_DIRNAME_MARKER in os.path.basename(dirpath).lower()
                for filename in filenames:
                    if len(found) >= LOG_SCAN_MAX_RESULTS:
                        break
                    if not (_looks_like_log(filename) or in_log_dir):
                        continue
                    full_path = os.path.join(dirpath, filename)
                    if os.path.isfile(full_path) and not os.path.islink(full_path):
                        found.add(full_path)
        except Exception:
            logger.exception("Fallo buscando logs en %s", root)

    return sorted(found), sorted(denied_dirs)


def detect_log_paths() -> dict:
    candidates: set[str] = set()
    for paths in WEB_SERVER_LOG_CANDIDATES.values():
        for path in paths:
            if os.path.exists(path):
                candidates.add(path)

    scanned, denied_dirs = _scan_for_log_files()
    candidates.update(scanned)

    # Encontrar un archivo (listar la carpeta que lo contiene) y poder leer
    # su contenido son dos permisos distintos en Linux -- hay que chequear
    # los dos para no vigilar a ciegas algo que el agente no va a poder
    # abrir nunca.
    readable = sorted(p for p in candidates if os.access(p, os.R_OK))
    unreadable = sorted(candidates - set(readable))

    return {"readable": readable, "unreadable": unreadable, "denied_dirs": denied_dirs}


def _is_system_account(entry: pwd.struct_passwd) -> bool:
    if entry.pw_name in WATCH_EXCLUDED_USERS:
        return False
    return entry.pw_shell in NOLOGIN_SHELLS or entry.pw_uid < SYSTEM_UID_MAX


def detect_service_accounts() -> list[str]:
    """Cualquier cuenta de sistema (no de login humano, por shell o por
    rango de UID -- convencion estandar de Debian/Ubuntu) que tenga un
    proceso activo en este momento, no solo una lista fija conocida. Que
    tenga un proceso corriendo ahora es lo que evita vigilar las decenas
    de cuentas de sistema que Debian crea pero nunca usa."""
    running_users: set[str] = set()
    try:
        for proc in psutil.process_iter(["username"]):
            username = proc.info.get("username")
            if username:
                running_users.add(username)
    except Exception:
        logger.exception("No se pudo listar procesos para detectar cuentas de servicio")

    system_accounts: set[str] = set()
    try:
        for entry in pwd.getpwall():
            if _is_system_account(entry):
                system_accounts.add(entry.pw_name)
    except Exception:
        logger.exception("No se pudo leer /etc/passwd para detectar cuentas de sistema")

    return sorted(running_users & system_accounts)


def full_report() -> dict:
    report = {**detect_os(), **detect_hardware()}
    report["services"] = detect_running_services()
    report["listening_ports"] = detect_listening_ports()
    log_info = detect_log_paths()
    report["log_paths"] = log_info["readable"]
    report["unreadable_log_paths"] = log_info["unreadable"]
    report["denied_log_dirs"] = log_info["denied_dirs"]
    report["service_accounts"] = detect_service_accounts()
    return report
PROXSECURE_EMBED_3_EOF

mkdir -p "$(dirname "$INSTALL_DIR/inventory.py")"
cat > "$INSTALL_DIR/inventory.py" <<'PROXSECURE_EMBED_4_EOF'
"""Inventario de paquetes instalados (dpkg), para que el servidor pueda
cruzarlo contra OSV.dev y detectar software con vulnerabilidades
conocidas. Solo funciona en sistemas basados en Debian/Ubuntu (como el
resto de este agente: fail2ban, apt, etc.).
"""

import logging
import subprocess

logger = logging.getLogger("inventory")


def collect() -> list[dict]:
    try:
        result = subprocess.run(
            ["dpkg-query", "-W", "-f=${Package}\t${Version}\n"],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        logger.warning("dpkg-query no disponible; este host no parece ser Debian/Ubuntu, salteando inventario")
        return []

    packages = []
    for line in result.stdout.splitlines():
        if "\t" not in line:
            continue
        name, version = line.split("\t", 1)
        packages.append({"name": name.strip(), "version": version.strip()})

    return packages


def debian_release() -> str | None:
    """VERSION_ID de /etc/os-release (ej. "11" para bullseye, "12" para
    bookworm). Necesario para consultar OSV.dev con el ecosistema
    correcto (Debian:11, Debian:12, ...), no solo "Debian" a secas."""
    try:
        with open("/etc/os-release", "r", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("VERSION_ID="):
                    return line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    return None
PROXSECURE_EMBED_4_EOF

mkdir -p "$(dirname "$INSTALL_DIR/log_tailer.py")"
cat > "$INSTALL_DIR/log_tailer.py" <<'PROXSECURE_EMBED_5_EOF'
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
    "PROX_SECURE_LOG_STATE", os.path.join(os.path.dirname(os.path.abspath(__file__)), "log_state.json")
)

_COMBINED_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+)[^"]*" '
    r'(?P<status>\d{3}) \S+ "[^"]*" "(?P<ua>[^"]*)"'
)


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

    return {
        "ts": ts.isoformat() if ts else None,
        "ip": groups["ip"],
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
PROXSECURE_EMBED_5_EOF

mkdir -p "$(dirname "$INSTALL_DIR/main.py")"
cat > "$INSTALL_DIR/main.py" <<'PROXSECURE_EMBED_6_EOF'
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
PROXSECURE_EMBED_6_EOF

mkdir -p "$(dirname "$INSTALL_DIR/metrics.py")"
cat > "$INSTALL_DIR/metrics.py" <<'PROXSECURE_EMBED_7_EOF'
import os
import time
from datetime import datetime, timezone

import psutil

# Para calcular Kbps de red hace falta la lectura anterior (los contadores
# de psutil son acumulados desde el boot, no una tasa). Se guarda en modulo
# porque metrics_loop llama collect() siempre desde el mismo proceso.
_last_net: tuple[float, int, int] | None = None


def _net_rates(net) -> tuple[float | None, float | None]:
    global _last_net
    now = time.monotonic()
    rx_kbps = tx_kbps = None

    if _last_net is not None:
        last_ts, last_rx, last_tx = _last_net
        elapsed = now - last_ts
        if elapsed > 0:
            rx_kbps = max(0.0, (net.bytes_recv - last_rx) * 8 / 1000 / elapsed)
            tx_kbps = max(0.0, (net.bytes_sent - last_tx) * 8 / 1000 / elapsed)

    _last_net = (now, net.bytes_recv, net.bytes_sent)
    return rx_kbps, tx_kbps


def collect() -> dict:
    cpu_total = psutil.cpu_percent(interval=1)
    cpu_times = psutil.cpu_times_percent(interval=None)  # misma ventana que el cpu_percent de arriba

    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()
    disk = psutil.disk_usage("/")
    net = psutil.net_io_counters()
    net_rx_kbps, net_tx_kbps = _net_rates(net)

    try:
        load1, load5, load15 = os.getloadavg()
    except (AttributeError, OSError):
        load1, load5, load15 = (None, None, None)

    return {
        "ts": datetime.now(timezone.utc).isoformat(),
        "cpu_percent": cpu_total,
        "cpu_user_percent": getattr(cpu_times, "user", None),
        "cpu_system_percent": getattr(cpu_times, "system", None),
        "cpu_iowait_percent": getattr(cpu_times, "iowait", None),  # no existe en Windows/macOS
        "cpu_steal_percent": getattr(cpu_times, "steal", None),  # solo tiene sentido en VMs Linux
        "mem_percent": mem.percent,
        "mem_used_mb": mem.used / (1024 * 1024),
        "mem_total_mb": mem.total / (1024 * 1024),
        "mem_available_mb": mem.available / (1024 * 1024),
        "mem_buffers_mb": getattr(mem, "buffers", 0) / (1024 * 1024),
        "mem_cached_mb": getattr(mem, "cached", 0) / (1024 * 1024),
        "mem_shared_mb": getattr(mem, "shared", 0) / (1024 * 1024),
        "swap_percent": swap.percent,
        "swap_used_mb": swap.used / (1024 * 1024),
        "swap_total_mb": swap.total / (1024 * 1024),
        "disk_percent": disk.percent,
        "disk_used_gb": disk.used / (1024 ** 3),
        "disk_total_gb": disk.total / (1024 ** 3),
        "load1": load1,
        "load5": load5,
        "load15": load15,
        "net_rx_bytes": net.bytes_recv,
        "net_tx_bytes": net.bytes_sent,
        "net_rx_kbps": net_rx_kbps,
        "net_tx_kbps": net_tx_kbps,
        "uptime_seconds": int(time.time() - psutil.boot_time()),
    }
PROXSECURE_EMBED_7_EOF

mkdir -p "$(dirname "$INSTALL_DIR/process_watch.py")"
cat > "$INSTALL_DIR/process_watch.py" <<'PROXSECURE_EMBED_8_EOF'
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
PROXSECURE_EMBED_8_EOF

mkdir -p "$(dirname "$INSTALL_DIR/requirements.txt")"
cat > "$INSTALL_DIR/requirements.txt" <<'PROXSECURE_EMBED_9_EOF'
psutil==6.1.0
httpx==0.27.2
PyYAML==6.0.2
PROXSECURE_EMBED_9_EOF

mkdir -p "$(dirname "$INSTALL_DIR/kill_process.sh")"
cat > "$INSTALL_DIR/kill_process.sh" <<'PROXSECURE_EMBED_10_EOF'
#!/usr/bin/env bash
# Mata un proceso SOLO si su cmdline actual todavia contiene la cadena
# esperada, para evitar matar un PID reciclado que ya no es el proceso
# que disparo la alerta. Pensado para correr via sudo (ver sudoers/).
set -euo pipefail

PID="${1:?uso: kill_process.sh <pid> <substring_esperado>}"
EXPECTED="${2:-}"

if [[ ! -r "/proc/$PID/cmdline" ]]; then
  echo "pid $PID ya no existe" >&2
  exit 1
fi

CMDLINE=$(tr '\0' ' ' < "/proc/$PID/cmdline")

if [[ -n "$EXPECTED" && "$CMDLINE" != *"$EXPECTED"* ]]; then
  echo "cmdline actual ('$CMDLINE') no coincide con lo esperado, aborto por seguridad" >&2
  exit 2
fi

kill -9 "$PID"
echo "pid $PID terminado (cmdline: $CMDLINE)"
PROXSECURE_EMBED_10_EOF
chmod 755 "$INSTALL_DIR/kill_process.sh"

if [[ ! -f "$INSTALL_DIR/config.yaml" ]]; then
mkdir -p "$(dirname "$INSTALL_DIR/config.yaml")"
cat > "$INSTALL_DIR/config.yaml" <<'PROXSECURE_EMBED_11_EOF'
# Copiar a config.yaml y completar con los datos reales del host.
server_url: "http://TU_SERVIDOR:8000"
api_key: "LA_API_KEY_DEL_HOST"

metrics_interval_seconds: 15

# El agente se autodescubre al arrancar (ver discovery.py): sistema
# operativo, servicios corriendo, puertos en escucha, y a partir de eso
# detecta que logs de servidor web y que cuentas de servicio tiene
# sentido vigilar EN ESTE HOST. No hace falta completar log_paths ni
# process_watch.service_users a mano -- dejalos vacios (como abajo) para
# que se autodetecten. Si los completas, lo que pongas aca gana siempre
# sobre lo autodetectado (por si el setup es no estandar).
log_paths: []

process_watch:
  interval_seconds: 10
  service_users: []

# Inventario de paquetes (dpkg) para el escaneo diario de vulnerabilidades
# en el servidor (OSV.dev). 86400s = 1 vez al dia.
inventory_interval_seconds: 86400

# Repetir el autodescubrimiento (por si se instala un servicio nuevo
# despues) y reenviar el informe de sistema. 86400s = 1 vez al dia.
discovery_interval_seconds: 86400

command_poll_interval_seconds: 10

# Nombre del jail de fail2ban usado para bloqueos manuales (ver
# agent/fail2ban/jail.d/proxsecure.conf).
fail2ban_jail: proxsecure
PROXSECURE_EMBED_11_EOF

  echo "Creado $INSTALL_DIR/config.yaml con valores de ejemplo."
  echo "Editalo para activar log_paths/service_users a mano si el autodescubrimiento no alcanza."
fi

python3 -m venv "$INSTALL_DIR/.venv"
"$INSTALL_DIR/.venv/bin/pip" install --no-cache-dir -r "$INSTALL_DIR/requirements.txt"

cat > "$INSTALL_DIR/.env" <<EOF
PROX_SECURE_SERVER_URL=${SERVER_URL}
PROX_SECURE_API_KEY=${API_KEY}
EOF
chmod 600 "$INSTALL_DIR/.env"

chown -R prox-secure:prox-secure "$INSTALL_DIR"

# fail2ban: jail dedicado para bloqueos manuales via panel
mkdir -p "$(dirname "/etc/fail2ban/filter.d/proxsecure.conf")"
cat > "/etc/fail2ban/filter.d/proxsecure.conf" <<'PROXSECURE_EMBED_12_EOF'
[Definition]
# Este filtro nunca matchea nada a proposito: el jail "proxsecure" solo se
# usa para bloqueos MANUALES disparados desde el panel
# (fail2ban-client set proxsecure banip/unbanip <ip>), no para deteccion
# automatica via fail2ban mismo (eso lo hace el motor IDS del servidor).
failregex = ^PROXSECURE_NUNCA_MATCHEA_ESTO$
ignoreregex =
PROXSECURE_EMBED_12_EOF

mkdir -p "$(dirname "/etc/fail2ban/jail.d/proxsecure.conf")"
cat > "/etc/fail2ban/jail.d/proxsecure.conf" <<'PROXSECURE_EMBED_13_EOF'
[proxsecure]
enabled = true
filter = proxsecure
logpath = /var/log/auth.log
backend = polling
maxretry = 999999
findtime = 86400
bantime = 3600
action = %(action_)s
PROXSECURE_EMBED_13_EOF

systemctl enable --now fail2ban
systemctl restart fail2ban

# sudo acotado: solo fail2ban-client (banip/unbanip) y el wrapper de kill
mkdir -p "$(dirname "/etc/sudoers.d/prox-secure-agent")"
cat > "/etc/sudoers.d/prox-secure-agent" <<'PROXSECURE_EMBED_14_EOF'

Cmnd_Alias PROXSECURE_CMDS = /usr/bin/fail2ban-client set * banip *, \
                              /usr/bin/fail2ban-client set * unbanip *, \
                              /opt/prox-secure-agent/kill_process.sh *

prox-secure ALL=(root) NOPASSWD: PROXSECURE_CMDS
PROXSECURE_EMBED_14_EOF
chmod 440 "/etc/sudoers.d/prox-secure-agent"

visudo -c -f /etc/sudoers.d/prox-secure-agent
mkdir -p "$(dirname "/etc/systemd/system/prox-secure-agent.service")"
cat > "/etc/systemd/system/prox-secure-agent.service" <<'PROXSECURE_EMBED_15_EOF'
[Unit]
Description=Prox Secure - agente de monitoreo
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/prox-secure-agent
EnvironmentFile=-/opt/prox-secure-agent/.env
ExecStart=/opt/prox-secure-agent/.venv/bin/python /opt/prox-secure-agent/main.py
Restart=on-failure
RestartSec=5
User=prox-secure
Group=prox-secure

[Install]
WantedBy=multi-user.target
PROXSECURE_EMBED_15_EOF

systemctl daemon-reload
systemctl enable prox-secure-agent
# restart (no start): si install.sh se re-corre sobre un agente que ya
# estaba activo, "start" no hace nada y el proceso se queda sin el grupo
# "adm" recien agregado hasta el proximo reinicio manual.
systemctl restart prox-secure-agent

echo "Agente instalado y corriendo. Ver logs: journalctl -u prox-secure-agent -f"
