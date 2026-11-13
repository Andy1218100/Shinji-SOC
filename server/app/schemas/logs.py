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
