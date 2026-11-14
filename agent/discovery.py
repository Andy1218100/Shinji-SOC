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

# cuentas de servicio candidatas: solo se reportan las que de verdad
# tienen un proceso corriendo con ese usuario en este host.
SERVICE_ACCOUNT_CANDIDATES = ("www-data", "nginx", "apache", "postgres", "mysql", "redis", "mongodb")


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


def detect_log_paths() -> list[str]:
    paths = []
    for candidates in WEB_SERVER_LOG_CANDIDATES.values():
        for path in candidates:
            if os.path.exists(path):
                paths.append(path)
    return paths


def detect_service_accounts() -> list[str]:
    running_users: set[str] = set()
    try:
        for proc in psutil.process_iter(["username"]):
            username = proc.info.get("username")
            if username:
                running_users.add(username)
    except Exception:
        logger.exception("No se pudo listar procesos para detectar cuentas de servicio")
    return sorted(u for u in SERVICE_ACCOUNT_CANDIDATES if u in running_users)


def full_report() -> dict:
    report = {**detect_os(), **detect_hardware()}
    report["services"] = detect_running_services()
    report["listening_ports"] = detect_listening_ports()
    report["log_paths"] = detect_log_paths()
    report["service_accounts"] = detect_service_accounts()
    return report
