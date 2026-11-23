from datetime import datetime

from pydantic import BaseModel, Field


class LogEntryIn(BaseModel):
    ts: datetime | None = None
    ip: str
    method: str | None = None
    path: str | None = None
    status_code: int | None = None
    user_agent: str | None = None
    # IP real que manda un proxy (CF-Connecting-IP o X-Forwarded-For), si el
    # log la trae. Solo se usa si "ip" es la de un proxy de confianza.
    forwarded_for: str | None = Field(default=None, max_length=200)


class LogBatchIn(BaseModel):
    entries: list[LogEntryIn]


class AuthEventIn(BaseModel):
    ts: datetime | None = None
    service: str = Field(pattern="^(ssh|pve)$")
    outcome: str = Field(pattern="^(failed|accepted|invalid_user)$")
    user: str | None = Field(default=None, max_length=64)
    ip: str = Field(max_length=64)
    method: str | None = Field(default=None, max_length=32)


class AuthEventBatchIn(BaseModel):
    entries: list[AuthEventIn] = Field(max_length=1000)


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
    # De donde lee el agente los logins SSH/Proxmox: "journal", la ruta de
    # auth.log, o None (no se vigilan). Agentes viejos no lo mandan.
    auth_log_source: str | None = None


class ListenerIn(BaseModel):
    proto: str = Field(pattern="^(tcp|udp)$")
    address: str = Field(max_length=64)
    port: int = Field(ge=0, le=65535)
    user: str | None = Field(default=None, max_length=64)
    process: str | None = Field(default=None, max_length=64)
    pid: int | None = None
    cmdline: str | None = Field(default=None, max_length=1000)


class OutboundIn(BaseModel):
    proto: str = Field(pattern="^(tcp|udp)$")
    local_port: int = Field(ge=0, le=65535)
    remote_ip: str = Field(max_length=64)
    remote_port: int = Field(ge=0, le=65535)
    user: str | None = Field(default=None, max_length=64)
    service_account: bool = False
    process: str | None = Field(default=None, max_length=64)
    pid: int | None = None
    cmdline: str | None = Field(default=None, max_length=1000)


class ConnectionsIn(BaseModel):
    """Lo que manda conn_watch.py del agente. listeners va completo (o null
    si no cambio desde el ultimo envio); outbound, solo las conexiones
    salientes nuevas."""
    listeners: list[ListenerIn] | None = Field(default=None, max_length=2000)
    outbound: list[OutboundIn] = Field(default_factory=list, max_length=2000)
