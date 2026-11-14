from datetime import datetime

from pydantic import BaseModel


class MetricIn(BaseModel):
    ts: datetime | None = None
    cpu_percent: float | None = None
    cpu_user_percent: float | None = None
    cpu_system_percent: float | None = None
    cpu_iowait_percent: float | None = None
    cpu_steal_percent: float | None = None
    mem_percent: float | None = None
    mem_used_mb: float | None = None
    mem_total_mb: float | None = None
    mem_available_mb: float | None = None
    mem_buffers_mb: float | None = None
    mem_cached_mb: float | None = None
    mem_shared_mb: float | None = None
    swap_percent: float | None = None
    swap_used_mb: float | None = None
    swap_total_mb: float | None = None
    disk_percent: float | None = None
    disk_used_gb: float | None = None
    disk_total_gb: float | None = None
    load1: float | None = None
    load5: float | None = None
    load15: float | None = None
    # float, no int: en rangos largos vienen promediados (time_bucket), asi
    # que pueden traer decimales aunque la fila original fuera un entero.
    net_rx_bytes: float | None = None
    net_tx_bytes: float | None = None
    net_rx_kbps: float | None = None
    net_tx_kbps: float | None = None
    uptime_seconds: float | None = None


class MetricOut(MetricIn):
    id: str | None = None
    host_id: str
    ts: datetime

    class Config:
        from_attributes = True
