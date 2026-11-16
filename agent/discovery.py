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
    import auth_watch  # aca para no cargar subprocess de journal al importar discovery

    report["auth_log_source"] = auth_watch.detect_source()
    return report
