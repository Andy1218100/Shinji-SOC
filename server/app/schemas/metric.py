from datetime import datetime

from pydantic import BaseModel


class MetricIn(BaseModel):
    ts: datetime | None = None
    cpu_percent: float | None = None
    mem_percent: float | None = None
    mem_used_mb: float | None = None
    mem_total_mb: float | None = None
    disk_percent: float | None = None
    disk_used_gb: float | None = None
    disk_total_gb: float | None = None
    load1: float | None = None
    load5: float | None = None
    load15: float | None = None
    net_rx_bytes: int | None = None
    net_tx_bytes: int | None = None
    uptime_seconds: int | None = None


class MetricOut(MetricIn):
    id: str
    host_id: str
    ts: datetime

    class Config:
        from_attributes = True
