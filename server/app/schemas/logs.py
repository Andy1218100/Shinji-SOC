from datetime import datetime

from pydantic import BaseModel


class LogEntryIn(BaseModel):
    ts: datetime | None = None
    ip: str
    method: str | None = None
    path: str | None = None
    status_code: int | None = None
    user_agent: str | None = None


class LogBatchIn(BaseModel):
    entries: list[LogEntryIn]


class ProcessEventIn(BaseModel):
    ts: datetime | None = None
    user: str
    pid: int
    cmdline: str
    parent_cmdline: str | None = None


class ProcessEventBatchIn(BaseModel):
    events: list[ProcessEventIn]


class PackageIn(BaseModel):
    name: str
    version: str
    # Paquete fuente de Debian (OSV indexa por fuente). Agentes viejos no lo
    # mandan: se usa el binario como fuente, como antes.
    source_name: str | None = None
    source_version: str | None = None


class InventoryIn(BaseModel):
    packages: list[PackageIn]
    debian_release: str | None = None  # VERSION_ID de /etc/os-release, ej. "11"


class ListeningPortIn(BaseModel):
    port: int
    process: str | None = None


class SystemReportIn(BaseModel):
    """Lo que el agente descubre de entrada, antes de arrancar a monitorear
    de forma continua. Se usa para armar el informe de IA y para que el
    propio agente personalice que logs/cuentas de servicio vigila."""

    os_name: str | None = None
    os_version_id: str | None = None
    kernel: str | None = None
    cpu_count: int | None = None
    mem_total_mb: float | None = None
    disk_total_gb: float | None = None
    services: list[str] = []
    listening_ports: list[ListeningPortIn] = []
    log_paths: list[str] = []
    # Encontrados por el escaneo de logs pero que el agente no puede leer
    # (unreadable_log_paths) o ni siquiera listar (denied_log_dirs, tipico
    # de apps que guardan todo bajo un directorio con permisos cerrados,
    # ej. ".ampdata" de AMP) -- separado de log_paths para poder avisar
    # del problema en vez de fallar en silencio.
    unreadable_log_paths: list[str] = []
    denied_log_dirs: list[str] = []
    service_accounts: list[str] = []
