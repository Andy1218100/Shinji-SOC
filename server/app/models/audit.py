import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class AIRule(Base):
    """Regla que un auditor externo (Claude, via el servidor MCP) le deja a la
    IA local despues de revisar sus respuestas. Se agrega al prompt de la IA
    local en las respuestas siguientes: asi la IA local mejora sin reentrenar
    el modelo (un 3B en CPU no se puede afinar desde aca)."""

    __tablename__ = "ai_rules"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    # A que tipo de respuesta aplica. Hoy solo "vuln_recommendation".
    scope: Mapped[str] = mapped_column(String(32), default="vuln_recommendation")
    # None = regla general; si no, solo para ese paquete fuente.
    package_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    rule: Mapped[str] = mapped_column(Text)
    source: Mapped[str] = mapped_column(String(32), default="claude")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
