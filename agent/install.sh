#!/usr/bin/env bash
# Instala el agente de Shinji SOC en un servidor Linux (Debian/Ubuntu).
# Autocontenido: alcanza con este archivo, no hace falta nada mas de este
# repo en el servidor. Generado por _build_install.sh -- no editar a mano
# los archivos embebidos de aca abajo, editar el fuente real en agent/ y
# volver a generar.
# Uso: sudo bash install.sh <server_url> <api_key>
set -euo pipefail

SERVER_URL="${1:?Falta server_url, ej: http://10.0.0.5:8000}"
API_KEY="${2:?Falta api_key del host (se genera al crear el host en el servidor)}"
INSTALL_DIR="/opt/shinji-soc-agent"
# Opcional: certificado raiz de la CA interna de Caddy (servidor con HTTPS en
# red local, ver docs/INSTALACION.md). Al reinstalar con ". .env && install.sh ..." se
# toma el que ya estaba configurado.
CA_FILE="${3:-${SHINJI_SOC_CA_FILE:-}}"
if [ -n "$CA_FILE" ] && [ ! -f "$CA_FILE" ]; then
  echo "No existe el certificado $CA_FILE" >&2
  exit 1
fi

if [[ $EUID -ne 0 ]]; then
  echo "Este script debe ejecutarse como root (sudo)." >&2
  exit 1
fi

# El proyecto se llamaba "Prox Secure": un agente de entonces usa otro
# usuario, servicio y carpeta, y quedarian los dos corriendo. Se quita
# primero con uninstall.sh (que reconoce los dos nombres).
if [ -d /opt/prox-secure-agent ] || [ -f /etc/systemd/system/prox-secure-agent.service ]; then
  echo "Hay un agente instalado con el nombre anterior (Prox Secure, en /opt/prox-secure-agent)." >&2
  echo "Quitalo primero y despues vuelve a correr este instalador:" >&2
  echo "  sudo grep API_KEY /opt/prox-secure-agent/.env    # anota la API key para reusarla" >&2
  echo "  sudo bash uninstall.sh --yes                     # el uninstall.sh de esta version" >&2
  exit 1
fi

# Dependencias del sistema. Se instalan siempre (apt no reinstala lo que
# ya esta, es rapido) en vez de detectar que falta uno por uno -- asi se
# evita el problema clasico de Debian donde python3 esta pero el modulo
# venv/pip no, porque van en paquetes separados (python3-venv, python3-pip).
# "sudo" se incluye a proposito: en hosts tipo hipervisor (Proxmox VE y
# similares, donde todo se maneja como root directamente) suele no venir
# instalado, y sin el no existe "visudo" (lo necesitamos mas abajo para
# validar el sudoers acotado del agente) ni funciona el bloqueo/kill/
# otorgamiento de acceso a logs aprobado desde el dashboard (commands.py
# invoca "sudo" en tiempo real). "acl" trae setfacl, que usa
# grant_log_access.sh para dar lectura puntual sin tocar duenos/permisos.
echo "Instalando dependencias del sistema (python3, venv, pip, sudo, fail2ban, acl)..."
apt-get update -y
apt-get install -y python3 python3-venv python3-pip sudo fail2ban acl

id -u shinji-soc &>/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin shinji-soc
# Grupo "adm": en Debian/Ubuntu es el dueno de lectura de /var/log/nginx,
# /var/log/apache2, etc. Sin esto, los logs que el agente autodetecta
# (ver discovery.py) existen pero no los puede leer.
usermod -aG adm shinji-soc

mkdir -p "$INSTALL_DIR"

echo "Escribiendo los archivos del agente en $INSTALL_DIR..."
mkdir -p "$(dirname "$INSTALL_DIR/commands.py")"
cat > "$INSTALL_DIR/commands.py" <<'SHINJISOC_EMBED_1_EOF'
"""Ejecuta comandos aprobados por el administrador desde el panel
(bloquear IP via fail2ban, terminar un proceso, dar acceso de lectura a
un log bloqueado) usando los permisos acotados definidos en
sudoers/shinji-soc-agent. El agente en si corre sin privilegios; solo
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
SHINJISOC_EMBED_1_EOF

mkdir -p "$(dirname "$INSTALL_DIR/config.py")"
cat > "$INSTALL_DIR/config.py" <<'SHINJISOC_EMBED_2_EOF'
import os
import sys

import yaml

CONFIG_PATH = os.environ.get(
    "SHINJI_SOC_CONFIG", os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.yaml")
)

_DEFAULTS = {
    "server_url": "http://localhost:8000",
    "api_key": "",
    "metrics_interval_seconds": 15,
    "log_paths": [],
    "process_watch": {"interval_seconds": 10, "service_users": []},
    "command_poll_interval_seconds": 10,
    "fail2ban_jail": "shinjisoc",
    "inventory_interval_seconds": 86400,
    "discovery_interval_seconds": 86400,
}


def load() -> dict:
    config = dict(_DEFAULTS)

    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
            config.update(yaml.safe_load(fh) or {})

    config["server_url"] = os.environ.get("SHINJI_SOC_SERVER_URL", config["server_url"])
    config["api_key"] = os.environ.get("SHINJI_SOC_API_KEY", config["api_key"])

    if not config["api_key"]:
        print("Falta api_key. Define config.yaml o SHINJI_SOC_API_KEY.", file=sys.stderr)
        sys.exit(1)

    return config
SHINJISOC_EMBED_2_EOF

mkdir -p "$(dirname "$INSTALL_DIR/discovery.py")"
cat > "$INSTALL_DIR/discovery.py" <<'SHINJISOC_EMBED_3_EOF'
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
WATCH_EXCLUDED_USERS = {"root", "shinji-soc"}
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
    import auth_watch  # aca para no cargar subprocess de journal al importar discovery

    report["auth_log_source"] = auth_watch.detect_source()
    return report
SHINJISOC_EMBED_3_EOF

mkdir -p "$(dirname "$INSTALL_DIR/inventory.py")"
cat > "$INSTALL_DIR/inventory.py" <<'SHINJISOC_EMBED_4_EOF'
"""Inventario de paquetes instalados (dpkg), para que el servidor pueda
cruzarlo contra OSV.dev y detectar software con vulnerabilidades
conocidas. Solo funciona en sistemas basados en Debian/Ubuntu (como el
resto de este agente: fail2ban, apt, etc.).
"""

import logging
import subprocess

import httpx

logger = logging.getLogger("inventory")


# ${source:Package}/${source:Version}: OSV indexa los avisos de Debian por
# paquete FUENTE. Consultando el binario, libssl3t64 devolvia 0 avisos y su
# fuente openssl 294 (medido); libc6 (fuente glibc) tampoco se revisaba.
# La version fuente tampoco es la del binario: bash 5.2.37-2+b10 viene del
# fuente 5.2.37-2, y bsdutils 1:2.41.5-... de util-linux 2.41.5-... (sin epoca).
DPKG_FORMAT = "${db:Status-Abbrev}\t${Package}\t${Version}\t${source:Package}\t${source:Version}\n"


def collect() -> list[dict]:
    try:
        result = subprocess.run(
            ["dpkg-query", "-W", f"-f={DPKG_FORMAT}"],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        logger.warning("dpkg-query no disponible; este host no parece ser Debian/Ubuntu, salteando inventario")
        return []

    # dict por nombre: con multiarch (amd64 + i386) dpkg lista el mismo
    # paquete una vez por arquitectura.
    packages: dict[str, dict] = {}
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) != 5:
            continue
        status, name, version, source_name, source_version = (p.strip() for p in parts)
        # "ii" = instalado. Los "rc" (desinstalados con config residual)
        # no tienen el binario y darian falsos positivos de CVE.
        if status != "ii":
            continue
        packages[name] = {
            "name": name,
            "version": version,
            "source_name": source_name or name,
            "source_version": source_version or version,
        }

    return list(packages.values())


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


async def send(client: httpx.AsyncClient, base_url: str, headers: dict) -> int:
    """Junta y manda el inventario. Devuelve cuantos paquetes mando (0 si
    no es un sistema con dpkg). Lanza excepcion si el servidor falla."""
    packages = collect()
    if not packages:
        return 0
    payload = {"packages": packages, "debian_release": debian_release()}
    resp = await client.post(f"{base_url}/api/v1/inventory/ingest", json=payload, headers=headers)
    resp.raise_for_status()
    return len(packages)
SHINJISOC_EMBED_4_EOF

mkdir -p "$(dirname "$INSTALL_DIR/auth_watch.py")"
cat > "$INSTALL_DIR/auth_watch.py" <<'SHINJISOC_EMBED_5_EOF'
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
SHINJISOC_EMBED_5_EOF

mkdir -p "$(dirname "$INSTALL_DIR/log_tailer.py")"
cat > "$INSTALL_DIR/log_tailer.py" <<'SHINJISOC_EMBED_6_EOF'
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
SHINJISOC_EMBED_6_EOF

mkdir -p "$(dirname "$INSTALL_DIR/main.py")"
cat > "$INSTALL_DIR/main.py" <<'SHINJISOC_EMBED_7_EOF'
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

Corre sin privilegios salvo las acciones puntuales de commands.py, que
usan sudo acotado (ver sudoers/shinji-soc-agent).
"""

import asyncio
import os
import logging

import httpx

import commands
import config
import discovery
import inventory
import auth_watch
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


async def discovery_loop(client: httpx.AsyncClient, base_url: str, headers: dict, interval: int) -> None:
    while True:
        await asyncio.sleep(interval)
        await send_system_report(client, base_url, headers)


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

    # Servidor con HTTPS de CA interna (Caddy "tls internal", red local):
    # SHINJI_SOC_CA_FILE apunta a su certificado raiz. Sin la variable se
    # usan las CAs del sistema (sirve para Let's Encrypt y para http://).
    verify = os.environ.get("SHINJI_SOC_CA_FILE") or True
    async with httpx.AsyncClient(timeout=30, verify=verify) as client:
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
            auth_loop(client, base_url, headers),
            inventory_loop(client, base_url, headers, cfg["inventory_interval_seconds"]),
            discovery_loop(client, base_url, headers, cfg["discovery_interval_seconds"]),
            commands_loop(client, base_url, headers, cfg["command_poll_interval_seconds"], cfg["fail2ban_jail"]),
        )


if __name__ == "__main__":
    asyncio.run(main())
SHINJISOC_EMBED_7_EOF

mkdir -p "$(dirname "$INSTALL_DIR/metrics.py")"
cat > "$INSTALL_DIR/metrics.py" <<'SHINJISOC_EMBED_8_EOF'
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
SHINJISOC_EMBED_8_EOF

mkdir -p "$(dirname "$INSTALL_DIR/process_watch.py")"
cat > "$INSTALL_DIR/process_watch.py" <<'SHINJISOC_EMBED_9_EOF'
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

# Scripts de sistema que corren legitimamente con un interprete de la lista
# de arriba bajo una cuenta de servicio. Coincidencia EXACTA de interprete +
# opciones + ruta del script, no "el script aparece en algun argumento":
# "perl -e CODIGO /usr/bin/pg_ctlcluster" corre CODIGO (con -e perl no busca
# archivo). Las opciones deben incluir -T: en modo taint perl ignora
# PERL5OPT/PERL5LIB/PERLLIB, asi que no se puede inyectar codigo por el
# entorno a un script permitido. Rutas en /usr/bin: la cuenta de servicio
# no puede reemplazarlas.
TRUSTED_SCRIPTS = {
    # systemd arranca/para PostgreSQL de Debian asi (postgresql@.service).
    ("perl", ("-wT",), "/usr/bin/pg_ctlcluster"),
    # Proxmox VE: interfaz web (puerto 8006) y proxy de consolas SPICE
    # (3128), corren como www-data. Reportados en un host real cada vez que
    # el agente se reiniciaba.
    ("perl", ("-T",), "/usr/bin/pveproxy"),
    ("perl", ("-T",), "/usr/bin/spiceproxy"),
}

_reported_pids: set[int] = set()


def _basename(cmdline: list[str]) -> str | None:
    if not cmdline:
        return None
    return os.path.basename(cmdline[0]).lower()


def _is_trusted_script(binary: str, cmdline: list[str]) -> bool:
    for interpreter, flags, script in TRUSTED_SCRIPTS:
        n = len(flags)
        if binary == interpreter and tuple(cmdline[1:1 + n]) == flags and cmdline[1 + n:2 + n] == [script]:
            return True
    return False


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
            if _is_trusted_script(binary, info["cmdline"]):
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
SHINJISOC_EMBED_9_EOF

mkdir -p "$(dirname "$INSTALL_DIR/requirements.txt")"
cat > "$INSTALL_DIR/requirements.txt" <<'SHINJISOC_EMBED_10_EOF'
psutil==6.1.0
httpx==0.27.2
PyYAML==6.0.2
SHINJISOC_EMBED_10_EOF

mkdir -p "$(dirname "$INSTALL_DIR/kill_process.sh")"
cat > "$INSTALL_DIR/kill_process.sh" <<'SHINJISOC_EMBED_11_EOF'
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
SHINJISOC_EMBED_11_EOF
chmod 755 "$INSTALL_DIR/kill_process.sh"

mkdir -p "$(dirname "$INSTALL_DIR/grant_log_access.sh")"
cat > "$INSTALL_DIR/grant_log_access.sh" <<'SHINJISOC_EMBED_12_EOF'
#!/usr/bin/env bash
# Da a shinji-soc permiso de LECTURA (via ACL -- nunca toca duenos ni
# permisos existentes, nunca agrega escritura) sobre una carpeta o
# archivo que discovery.py encontro pero no pudo abrir/leer. Pensado
# para correr via sudo (ver sudoers/shinji-soc-agent).
#
# Solo opera dentro de las mismas rutas donde discovery.py busca logs
# (ver LOG_SCAN_ROOTS en discovery.py) -- y nunca sobre /root: el riesgo
# de dar lectura recursiva al home de root (claves SSH, etc.) no vale la
# pena por un log que casi seguro no esta ahi. Si el log que falta
# resulta estar en /root, hay que revisarlo a mano por ssh.
set -euo pipefail

TARGET="${1:?uso: grant_log_access.sh <ruta absoluta>}"

if [[ "$TARGET" != /* ]]; then
  echo "la ruta debe ser absoluta" >&2
  exit 1
fi

if [[ ! -e "$TARGET" ]]; then
  echo "la ruta no existe: $TARGET" >&2
  exit 1
fi

RESOLVED=$(realpath -e "$TARGET")

ALLOWED_PREFIXES=("/var/log" "/opt" "/srv" "/home")
allowed=0
for prefix in "${ALLOWED_PREFIXES[@]}"; do
  if [[ "$RESOLVED" == "$prefix" || "$RESOLVED" == "$prefix"/* ]]; then
    allowed=1
    break
  fi
done
if [[ "$allowed" -ne 1 ]]; then
  echo "ruta fuera de lo permitido ($RESOLVED) -- solo /var/log, /opt, /srv o /home (nunca /root)" >&2
  exit 2
fi

if ! command -v setfacl &>/dev/null; then
  echo "setfacl no esta instalado (paquete 'acl')" >&2
  exit 3
fi

if [[ -d "$RESOLVED" ]]; then
  # rX en vez de rx: la X mayuscula solo da ejecucion (necesaria para
  # poder "entrar") a lo que ya es un directorio, nunca a un archivo
  # suelto -- no vuelve ejecutable nada que no lo fuera.
  setfacl -R -m u:shinji-soc:rX "$RESOLVED"
  # ACL por defecto: para que los logs que esa app cree DESPUES de hoy
  # (rotacion diaria, nuevas instancias, etc.) hereden el mismo permiso
  # sin tener que repetir esto cada vez.
  setfacl -R -d -m u:shinji-soc:rX "$RESOLVED"
else
  setfacl -m u:shinji-soc:r "$RESOLVED"
fi

# Lista de rutas otorgadas, para que uninstall.sh las quite sin tener que
# recorrer todo /home y /opt buscando ACLs.
GRANTED="$(dirname "$(realpath "$0")")/granted_paths"
grep -qxF "$RESOLVED" "$GRANTED" 2>/dev/null || echo "$RESOLVED" >> "$GRANTED"

echo "acceso de lectura otorgado a shinji-soc sobre $RESOLVED"
SHINJISOC_EMBED_12_EOF
chmod 755 "$INSTALL_DIR/grant_log_access.sh"

mkdir -p "$(dirname "/usr/local/sbin/shinji-soc-uninstall")"
cat > "/usr/local/sbin/shinji-soc-uninstall" <<'SHINJISOC_EMBED_13_EOF'
#!/usr/bin/env bash
# Quita el agente de Shinji SOC de este host: todo lo que puso install.sh.
# Tambien quita un agente instalado con el nombre anterior del proyecto
# (Prox Secure: /opt/prox-secure-agent, usuario prox-secure).
#
# Uso (como root):
#   shinji-soc-uninstall              pide confirmacion
#   shinji-soc-uninstall --dry-run    solo muestra lo que haria
#   shinji-soc-uninstall --yes        sin preguntar
# (install.sh lo deja instalado como /usr/local/sbin/shinji-soc-uninstall;
# tambien se puede copiar y correr con "sudo bash uninstall.sh".)
#
# Quita: el servicio, la carpeta del agente en /opt (incluida su API key),
# el sudoers del agente, su jail de fail2ban (las IPs bloqueadas desde el
# panel quedan desbloqueadas), los permisos de lectura (ACL) que se dieron
# desde el panel con "Dar acceso", y el usuario del agente.
#
# No quita los paquetes que instalo install.sh (python3-venv, fail2ban,
# acl, sudo): pueden estar en uso por otras cosas. Tampoco toca el
# servidor: el host y su historial se borran desde el panel.
set -uo pipefail

ACL_ROOTS=(/var/log /opt /srv /home)   # los mismos que permite grant_log_access.sh

# Cada instalacion: nombre|carpeta|servicio|usuario|sudoers|jail|log de fail2ban|comando
INSTALLS=(
  "Shinji SOC|/opt/shinji-soc-agent|shinji-soc-agent|shinji-soc|/etc/sudoers.d/shinji-soc-agent|shinjisoc|/var/log/shinji-soc-fail2ban.log|/usr/local/sbin/shinji-soc-uninstall"
  "Prox Secure (nombre anterior)|/opt/prox-secure-agent|prox-secure-agent|prox-secure|/etc/sudoers.d/prox-secure-agent|proxsecure|/var/log/prox-secure-fail2ban.log|/usr/local/sbin/prox-secure-uninstall"
)

DRY_RUN=0
ASSUME_YES=0
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    -y|--yes) ASSUME_YES=1 ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "Opcion desconocida: $arg (usa --dry-run, --yes o --help)" >&2; exit 2 ;;
  esac
done

if [ "$EUID" -ne 0 ] && [ "$DRY_RUN" -eq 0 ]; then
  echo "Hay que correrlo como root (sudo)." >&2
  exit 1
fi

run() {
  # Muestra cada accion; en --dry-run no la ejecuta.
  echo "  + $*"
  if [ "$DRY_RUN" -eq 0 ]; then
    "$@" || echo "    (fallo, se sigue con el resto)" >&2
  fi
}

have() { command -v "$1" >/dev/null 2>&1; }

echo "Desinstalacion del agente de Shinji SOC en $(hostname)"
[ "$DRY_RUN" -eq 1 ] && echo "(simulacion: no se cambia nada)"

# Rutas donde "Dar acceso" (grant_log_access.sh) dio lectura a $user, sin
# las que quedan dentro de otra de la lista (se quitan juntas, con -R).
# Primero, la lista que guarda grant_log_access.sh. Los agentes anteriores
# no la tienen: entonces se busca, pero no archivo por archivo en todo el
# arbol (con carpetas de cientos de miles de archivos tardaba demasiado),
# sino en las carpetas (Dar acceso sobre una carpeta deja una ACL en ella)
# y en los archivos con nombre de log (Dar acceso sobre un archivo suelto:
# discovery.py solo ofrece logs).
acl_paths() {
  local user="$1" dir="$2" roots=() r
  if [ -f "$dir/granted_paths" ]; then
    while IFS= read -r r; do [ -e "$r" ] && printf '%s\n' "$r"; done < "$dir/granted_paths"
    return
  fi
  for r in "${ACL_ROOTS[@]}"; do [ -e "$r" ] && roots+=("$r"); done
  [ "${#roots[@]}" -eq 0 ] && return
  echo "  Buscando permisos de lectura de $user en ${roots[*]} (con carpetas muy grandes puede tardar unos minutos)..." >&2
  {
    find "${roots[@]}" -xdev -type d -print0 2>/dev/null
    find "${roots[@]}" -xdev -type f \( -name '*.log' -o -name '*.log.*' -o -name '*.logs' \
      -o -path '*/log/*' -o -path '*/logs/*' \) -print0 2>/dev/null
  } | xargs -0 -r getfacl -s -p 2>/dev/null | awk -v u="$user" '
      /^# file: / { file = substr($0, 9); next }
      $0 ~ "^(default:)?user:" u ":" { if (!(file in seen)) { seen[file] = 1; print file } }' \
    | grep -v -e "^$dir\$" -e "^$dir/" \
    | LC_ALL=C sort | awk '{ if (top != "" && index($0, top "/") == 1) next; print; top = $0 }'
}

# --- que hay instalado de cada nombre
found_any=0
declare -A ACL_PATHS FOUND
for entry in "${INSTALLS[@]}"; do
  IFS='|' read -r label dir service user sudoers jail f2blog self <<<"$entry"
  found=0
  lines=()
  [ -d "$dir" ] && { lines+=("agente en $dir"); found=1; }
  [ -f "/etc/systemd/system/$service.service" ] && { lines+=("servicio $service"); found=1; }
  [ -f "$sudoers" ] && { lines+=("sudoers $sudoers"); found=1; }
  [ -f "/etc/fail2ban/jail.d/$jail.conf" ] && { lines+=("jail $jail de fail2ban"); found=1; }
  id -u "$user" >/dev/null 2>&1 && { lines+=("usuario $user"); found=1; }

  # Permisos de lectura (ACL) que dio "Dar acceso". Se buscan antes de
  # borrar el usuario: despues getfacl solo mostraria su numero.
  paths=""
  if have getfacl && id -u "$user" >/dev/null 2>&1; then
    paths=$(acl_paths "$user" "$dir")
    total=$(printf '%s' "$paths" | grep -c . || true)
    [ "$total" -gt 0 ] && { lines+=("permisos de lectura (ACL) de $user en $total rutas"); found=1; }
  fi
  ACL_PATHS[$user]="$paths"
  FOUND[$user]=$found

  if [ "$found" -eq 1 ]; then
    found_any=1
    echo
    echo "$label:"
    for l in "${lines[@]}"; do echo "- $l"; done
    if have fail2ban-client && fail2ban-client status "$jail" >/dev/null 2>&1; then
      banned=$(fail2ban-client status "$jail" 2>/dev/null | sed -n 's/.*Banned IP list:[[:space:]]*//p')
      [ -n "$banned" ] && echo "  IPs bloqueadas desde el panel que quedaran desbloqueadas: $banned"
    fi
  fi
done

if [ "$found_any" -eq 0 ]; then
  echo
  echo "No hay nada del agente instalado en este host."
  if [ "$DRY_RUN" -eq 0 ]; then
    for entry in "${INSTALLS[@]}"; do
      IFS='|' read -r _ _ _ _ _ _ _ self <<<"$entry"
      [ -f "$self" ] && rm -f "$self"
    done
  fi
  exit 0
fi

if [ "$DRY_RUN" -eq 0 ] && [ "$ASSUME_YES" -eq 0 ]; then
  echo
  read -r -p "Escribe QUITAR para desinstalar el agente: " answer
  [ "$answer" = "QUITAR" ] || { echo "Cancelado."; exit 1; }
fi

restart_f2b=0
for entry in "${INSTALLS[@]}"; do
  IFS='|' read -r label dir service user sudoers jail f2blog self <<<"$entry"
  [ "${FOUND[$user]}" -eq 1 ] || continue
  echo
  echo "== $label"

  echo "1/6 Servicio"
  if [ -f "/etc/systemd/system/$service.service" ]; then
    have systemctl && run systemctl disable --now "$service"
    run rm -f "/etc/systemd/system/$service.service"
    have systemctl && run systemctl daemon-reload
  else
    echo "  (no esta)"
  fi

  echo "2/6 Jail $jail de fail2ban"
  if [ -f "/etc/fail2ban/jail.d/$jail.conf" ] || [ -f "/etc/fail2ban/filter.d/$jail.conf" ]; then
    run rm -f "/etc/fail2ban/jail.d/$jail.conf" "/etc/fail2ban/filter.d/$jail.conf" "$f2blog"
    restart_f2b=1
  else
    echo "  (no esta)"
  fi

  echo "3/6 Permisos de lectura (ACL)"
  [ -z "${ACL_PATHS[$user]}" ] && echo "  (ninguno)"
  while IFS= read -r p; do
    [ -n "$p" ] || continue
    if [ -d "$p" ]; then
      # La carpeta y todo lo de adentro de una vez: la entrada de acceso
      # (archivos y carpetas) y la entrada por defecto (solo carpetas).
      run setfacl -R -x "u:$user" "$p"
      run find "$p" -xdev -type d -exec setfacl -x "d:u:$user" {} +
    else
      run setfacl -x "u:$user" "$p"
    fi
  done <<<"${ACL_PATHS[$user]}"

  echo "4/6 Sudoers"
  if [ -f "$sudoers" ]; then
    run rm -f "$sudoers"
  else
    echo "  (no esta)"
  fi

  echo "5/6 Usuario $user"
  if id -u "$user" >/dev/null 2>&1; then
    # Por si quedo algun proceso suyo (el servicio ya se detuvo).
    have pkill && run pkill -u "$user"
    run userdel "$user"
    getent group "$user" >/dev/null 2>&1 && run groupdel "$user"
  else
    echo "  (no esta)"
  fi

  echo "6/6 Archivos del agente"
  if [ -d "$dir" ]; then
    run rm -rf "$dir"
  else
    echo "  (no estan)"
  fi
done

# Reiniciar fail2ban saca los jails borrados y sus bloqueos; el resto de
# los jails sigue igual.
if [ "$restart_f2b" -eq 1 ] && have systemctl && systemctl is-active --quiet fail2ban; then
  echo
  run systemctl restart fail2ban
fi

echo
if [ "$DRY_RUN" -eq 1 ]; then
  echo "Simulacion terminada: no se cambio nada."
else
  for entry in "${INSTALLS[@]}"; do
    IFS='|' read -r _ _ _ _ _ _ _ self <<<"$entry"
    [ -f "$self" ] && rm -f "$self"
  done
  echo "Agente quitado de $(hostname)."
  echo "Los paquetes (python3-venv, fail2ban, acl, sudo) quedan instalados."
  echo "Para borrar tambien el host y su historial del panel: Monitoreo > el host > Eliminar (pide MFA)."
fi
SHINJISOC_EMBED_13_EOF
chmod 755 "/usr/local/sbin/shinji-soc-uninstall"

if [[ ! -f "$INSTALL_DIR/config.yaml" ]]; then
mkdir -p "$(dirname "$INSTALL_DIR/config.yaml")"
cat > "$INSTALL_DIR/config.yaml" <<'SHINJISOC_EMBED_14_EOF'
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
# agent/fail2ban/jail.d/shinjisoc.conf).
fail2ban_jail: shinjisoc
SHINJISOC_EMBED_14_EOF

  echo "Creado $INSTALL_DIR/config.yaml con valores de ejemplo."
  echo "Editalo para activar log_paths/service_users a mano si el autodescubrimiento no alcanza."
fi

python3 -m venv "$INSTALL_DIR/.venv"
"$INSTALL_DIR/.venv/bin/pip" install --no-cache-dir -r "$INSTALL_DIR/requirements.txt"

cat > "$INSTALL_DIR/.env" <<EOF
SHINJI_SOC_SERVER_URL=${SERVER_URL}
SHINJI_SOC_API_KEY=${API_KEY}
EOF
if [ -n "$CA_FILE" ]; then
  if [ "$(realpath "$CA_FILE")" != "$INSTALL_DIR/ca.crt" ]; then
    cp "$CA_FILE" "$INSTALL_DIR/ca.crt"
  fi
  echo "SHINJI_SOC_CA_FILE=$INSTALL_DIR/ca.crt" >> "$INSTALL_DIR/.env"
  echo "Usando la CA de $CA_FILE para verificar el HTTPS del servidor."
fi
chmod 600 "$INSTALL_DIR/.env"

chown -R shinji-soc:shinji-soc "$INSTALL_DIR"

# fail2ban: jail dedicado para bloqueos manuales via panel
mkdir -p "$(dirname "/etc/fail2ban/filter.d/shinjisoc.conf")"
cat > "/etc/fail2ban/filter.d/shinjisoc.conf" <<'SHINJISOC_EMBED_15_EOF'
[Definition]
# Este filtro nunca matchea nada a proposito: el jail "shinjisoc" solo se
# usa para bloqueos MANUALES disparados desde el panel
# (fail2ban-client set shinjisoc banip/unbanip <ip>), no para deteccion
# automatica via fail2ban mismo (eso lo hace el motor IDS del servidor).
# fail2ban exige <HOST> en todo failregex: sin el rechaza la configuracion
# ("No failure-id group") y no arranca ningun jail, ni el sshd de Debian.
# El archivo que lee el jail esta siempre vacio, asi que nunca coincide.
failregex = ^SHINJISOC_NUNCA_MATCHEA_ESTO <HOST>$
ignoreregex =
SHINJISOC_EMBED_15_EOF

mkdir -p "$(dirname "/etc/fail2ban/jail.d/shinjisoc.conf")"
cat > "/etc/fail2ban/jail.d/shinjisoc.conf" <<'SHINJISOC_EMBED_16_EOF'
# logpath: archivo propio y vacio (lo crea install.sh). El filtro nunca
# matchea: este jail solo recibe bloqueos manuales desde el panel.
[shinjisoc]
enabled = true
filter = shinjisoc
logpath = /var/log/shinji-soc-fail2ban.log
backend = polling
maxretry = 999999
findtime = 86400
bantime = 3600
action = %(action_)s
SHINJISOC_EMBED_16_EOF

# El jail no lee logs (solo recibe bloqueos manuales), pero fail2ban exige
# que el logpath exista. Antes era /var/log/auth.log, que no existe en
# Proxmox VE 8+ (sin rsyslog): el jail no arrancaba y bloquear no hacia nada.
touch /var/log/shinji-soc-fail2ban.log
systemctl enable --now fail2ban
systemctl restart fail2ban
# Sin esto un error de configuracion pasaba en silencio: fail2ban arranca,
# falla al cargar los jails y se cierra, y "Bloquear IP" no hace nada.
sleep 2
if systemctl is-active --quiet fail2ban && fail2ban-client status shinjisoc >/dev/null 2>&1; then
  echo "fail2ban activo con el jail shinjisoc (bloqueos desde el panel)."
else
  echo "AVISO: fail2ban no quedo activo, los bloqueos de IP desde el panel no van a funcionar." >&2
  echo "       Revisa: fail2ban-client -t; tail -n 30 /var/log/fail2ban.log" >&2
fi

# sudo acotado: solo fail2ban-client (banip/unbanip) y el wrapper de kill
mkdir -p "$(dirname "/etc/sudoers.d/shinji-soc-agent")"
cat > "/etc/sudoers.d/shinji-soc-agent" <<'SHINJISOC_EMBED_17_EOF'

Cmnd_Alias SHINJISOC_CMDS = /usr/bin/fail2ban-client set * banip *, \
                              /usr/bin/fail2ban-client set * unbanip *, \
                              /opt/shinji-soc-agent/kill_process.sh *, \
                              /opt/shinji-soc-agent/grant_log_access.sh *

shinji-soc ALL=(root) NOPASSWD: SHINJISOC_CMDS
SHINJISOC_EMBED_17_EOF
chmod 440 "/etc/sudoers.d/shinji-soc-agent"

visudo -c -f /etc/sudoers.d/shinji-soc-agent
mkdir -p "$(dirname "/etc/systemd/system/shinji-soc-agent.service")"
cat > "/etc/systemd/system/shinji-soc-agent.service" <<'SHINJISOC_EMBED_18_EOF'
[Unit]
Description=Shinji SOC - agente de monitoreo
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/shinji-soc-agent
EnvironmentFile=-/opt/shinji-soc-agent/.env
ExecStart=/opt/shinji-soc-agent/.venv/bin/python /opt/shinji-soc-agent/main.py
Restart=on-failure
RestartSec=5
User=shinji-soc
Group=shinji-soc

[Install]
WantedBy=multi-user.target
SHINJISOC_EMBED_18_EOF

systemctl daemon-reload
systemctl enable shinji-soc-agent
# restart (no start): si install.sh se re-corre sobre un agente que ya
# estaba activo, "start" no hace nada y el proceso se queda sin el grupo
# "adm" recien agregado hasta el proximo reinicio manual.
systemctl restart shinji-soc-agent

echo "Agente instalado y corriendo. Ver logs: journalctl -u shinji-soc-agent -f"
