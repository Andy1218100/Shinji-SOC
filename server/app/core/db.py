from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.core.config import settings

engine = create_async_engine(settings.database_url, echo=False)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


async def get_db() -> AsyncSession:
    async with SessionLocal() as session:
        yield session


async def ensure_columns(conn: AsyncConnection) -> None:
    """No hay migraciones y `create_all` no agrega columnas a una tabla que
    ya existe: las columnas nuevas se agregan aca, idempotente."""
    for stmt in (
        "ALTER TABLE vulnerability_findings ADD COLUMN IF NOT EXISTS urgency VARCHAR(32)",
        "ALTER TABLE installed_packages ADD COLUMN IF NOT EXISTS source_name VARCHAR(255)",
        "ALTER TABLE installed_packages ADD COLUMN IF NOT EXISTS source_version VARCHAR(255)",
        "ALTER TABLE vulnerability_findings ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMPTZ",
        "ALTER TABLE vulnerability_findings ADD COLUMN IF NOT EXISTS resolution VARCHAR(255)",
        "ALTER TABLE vulnerability_findings ADD COLUMN IF NOT EXISTS not_applicable VARCHAR(255)",
        "ALTER TABLE hosts ADD COLUMN IF NOT EXISTS last_vuln_scan_at TIMESTAMPTZ",
    ):
        await conn.execute(text(stmt))


async def ensure_hypertables(conn: AsyncConnection) -> None:
    """La imagen es TimescaleDB pero `create_all` crea tablas Postgres
    normales -- esto las convierte a hypertable (particionado por tiempo)
    la primera vez. Idempotente: no hace nada si ya lo es. migrate_data
    porque `metrics` puede tener filas de antes de este cambio."""
    await conn.execute(
        text(
            "SELECT create_hypertable('metrics', 'ts', if_not_exists => TRUE, migrate_data => TRUE)"
        )
    )
