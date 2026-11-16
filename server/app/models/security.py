import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Integer, JSON, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    host_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("hosts.id"), index=True)

    kind: Mapped[str] = mapped_column(String(32))  # path_scan | brute_force | process_anomaly | ssh_brute_force | pve_brute_force | login_after_failures
    severity: Mapped[str] = mapped_column(String(16), default="warning")  # info|warning|critical
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)  # evidencia cruda (rutas, cmdline, etc.)

    suggested_action: Mapped[str | None] = mapped_column(String(32), nullable=True)  # block_ip|kill_process
    status: Mapped[str] = mapped_column(String(16), default="open")  # open|approved|dismissed

    ai_summary: Mapped[str | None] = mapped_column(Text, nullable=True)

    geo_country: Mapped[str | None] = mapped_column(String(64), nullable=True)
    geo_city: Mapped[str | None] = mapped_column(String(128), nullable=True)
    geo_lat: Mapped[float | None] = mapped_column(Float, nullable=True)
    geo_lon: Mapped[float | None] = mapped_column(Float, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Command(Base):
    __tablename__ = "commands"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    host_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("hosts.id"), index=True)
    security_event_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("security_events.id"), nullable=True
    )

    action: Mapped[str] = mapped_column(String(32))  # block_ip|unblock_ip|kill_process
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(16), default="pending")  # pending|done|failed

    result: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class BlockedIP(Base):
    __tablename__ = "blocked_ips"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    host_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("hosts.id"), index=True)
    ip: Mapped[str] = mapped_column(String(64), index=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    blocked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    unblocked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AuthAttempt(Base):
    """Intentos de login (SSH y web de Proxmox) que manda el agente ya
    parseados. Ventana corta para detectar fuerza bruta; se purgan segun
    RETENTION_REQUESTS_DAYS (ver services/retention.py)."""

    __tablename__ = "auth_attempts"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    host_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("hosts.id"), index=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    service: Mapped[str] = mapped_column(String(8))  # ssh | pve
    outcome: Mapped[str] = mapped_column(String(16))  # failed | accepted | invalid_user
    username: Mapped[str | None] = mapped_column(String(64), nullable=True)
    ip: Mapped[str] = mapped_column(String(64), index=True)
    method: Mapped[str | None] = mapped_column(String(32), nullable=True)


class IngestedRequest(Base):
    """Ventana corta de requests crudas para scoring de IDS (fuerza bruta / escaneo)."""

    __tablename__ = "ingested_requests"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    host_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("hosts.id"), index=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    ip: Mapped[str] = mapped_column(String(64), index=True)
    method: Mapped[str | None] = mapped_column(String(16), nullable=True)
    path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)
