import uuid
from datetime import datetime

from sqlalchemy import DateTime, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class Host(Base):
    __tablename__ = "hosts"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), unique=True)
    hostname: Mapped[str] = mapped_column(String(255))
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    os: Mapped[str | None] = mapped_column(String(128), nullable=True)
    debian_release: Mapped[str | None] = mapped_column(String(16), nullable=True)
    api_key: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_vuln_scan_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
