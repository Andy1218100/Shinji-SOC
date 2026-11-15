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
LOG_DIRNAME_MARKERS = ("log", "logs")
LOG_SCAN_MAX_DEPTH = 6
LOG_SCAN_MAX_DIRS = 2000  # tope de directorios visitados, para no colgarse en arboles enormes
LOG_SCAN_MAX_RESULTS = 40


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


def _scan_for_log_files() -> list[str]:
    """Busqueda acotada (no toda la raiz, con tope de carpetas y resultados)
    de cualquier archivo que parezca un log, mas alla de los paths fijos de
    nginx/apache. Que un archivo aparezca aca no garantiza que sea un log
    de acceso HTTP util para el IDS -- el parser de logs ya ignora en
    silencio cualquier linea que no tenga el formato esperado, asi que el
    costo de vigilar uno que no sirve es nomas un poco de I/O, nunca un
    error. Se prioriza mostrar todo lo que puede ser relevante (lo pidio
    el usuario explicitamente) por sobre ser quirurgico."""
    found: set[str] = set()
    visited_dirs = 0

    for root in LOG_SCAN_ROOTS:
        if len(found) >= LOG_SCAN_MAX_RESULTS or visited_dirs >= LOG_SCAN_MAX_DIRS:
            break
        if not os.path.isdir(root):
            continue

        base_depth = root.rstrip(os.sep).count(os.sep)
        try:
            walker = os.walk(root, onerror=lambda e: None)
            for dirpath, dirnames, filenames in walker:
                visited_dirs += 1
                depth = dirpath.rstrip(os.sep).count(os.sep) - base_depth

                if visited_dirs >= LOG_SCAN_MAX_DIRS or len(found) >= LOG_SCAN_MAX_RESULTS:
                    dirnames[:] = []
                    break
                if depth >= LOG_SCAN_MAX_DEPTH:
                    dirnames[:] = []  # no seguir bajando en este subarbol

                in_log_dir = os.path.basename(dirpath).lower() in LOG_DIRNAME_MARKERS
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

    return sorted(found)


def detect_log_paths() -> list[str]:
    paths: set[str] = set()
    for candidates in WEB_SERVER_LOG_CANDIDATES.values():
        for path in candidates:
            if os.path.exists(path):
                paths.add(path)
    paths.update(_scan_for_log_files())
    return sorted(paths)


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
    report["log_paths"] = detect_log_paths()
    report["service_accounts"] = detect_service_accounts()
    return report
