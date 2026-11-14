import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, BigInteger
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class Metric(Base):
    __tablename__ = "metrics"

    # PK compuesta (id, ts): TimescaleDB exige que cualquier clave unica de
    # un hypertable incluya la columna de particionado (ts). `id` solo ya
    # es unico en la practica (uuid4), esto es para que Timescale lo acepte.
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    host_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("hosts.id"), index=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), primary_key=True, index=True)

    cpu_percent: Mapped[float | None] = mapped_column(Float, nullable=True)
    cpu_user_percent: Mapped[float | None] = mapped_column(Float, nullable=True)
    cpu_system_percent: Mapped[float | None] = mapped_column(Float, nullable=True)
    cpu_iowait_percent: Mapped[float | None] = mapped_column(Float, nullable=True)
    cpu_steal_percent: Mapped[float | None] = mapped_column(Float, nullable=True)
    mem_percent: Mapped[float | None] = mapped_column(Float, nullable=True)
    mem_used_mb: Mapped[float | None] = mapped_column(Float, nullable=True)
    mem_total_mb: Mapped[float | None] = mapped_column(Float, nullable=True)
    mem_available_mb: Mapped[float | None] = mapped_column(Float, nullable=True)
    mem_buffers_mb: Mapped[float | None] = mapped_column(Float, nullable=True)
    mem_cached_mb: Mapped[float | None] = mapped_column(Float, nullable=True)
    mem_shared_mb: Mapped[float | None] = mapped_column(Float, nullable=True)
    swap_percent: Mapped[float | None] = mapped_column(Float, nullable=True)
    swap_used_mb: Mapped[float | None] = mapped_column(Float, nullable=True)
    swap_total_mb: Mapped[float | None] = mapped_column(Float, nullable=True)
    disk_percent: Mapped[float | None] = mapped_column(Float, nullable=True)
    disk_used_gb: Mapped[float | None] = mapped_column(Float, nullable=True)
    disk_total_gb: Mapped[float | None] = mapped_column(Float, nullable=True)
    load1: Mapped[float | None] = mapped_column(Float, nullable=True)
    load5: Mapped[float | None] = mapped_column(Float, nullable=True)
    load15: Mapped[float | None] = mapped_column(Float, nullable=True)
    net_rx_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    net_tx_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    net_rx_kbps: Mapped[float | None] = mapped_column(Float, nullable=True)
    net_tx_kbps: Mapped[float | None] = mapped_column(Float, nullable=True)
    uptime_seconds: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
