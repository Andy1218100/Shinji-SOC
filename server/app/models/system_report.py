import uuid
from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class SystemReport(Base):
    """Fotografia del sistema que reporta el agente (una por host, se
    reemplaza en cada reporte -- no es historico). `raw` es el payload tal
    como lo mando el agente; `ai_summary` es la lectura en lenguaje natural
    que arma la IA a partir de esos mismos datos, nunca inventados."""

    __tablename__ = "system_reports"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    host_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("hosts.id"), unique=True)
    raw: Mapped[dict] = mapped_column(JSON, default=dict)
    ai_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    generated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
