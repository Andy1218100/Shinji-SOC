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
    service_accounts: list[str] = []
