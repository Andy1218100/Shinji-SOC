from fastapi import Depends, Header, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.db import get_db
from app.models.host import Host


async def require_admin(x_admin_key: str = Header(default="")) -> None:
    if x_admin_key != settings.admin_api_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Admin key invalida")


async def get_current_host(
    x_api_key: str = Header(default=""),
    db: AsyncSession = Depends(get_db),
) -> Host:
    result = await db.execute(select(Host).where(Host.api_key == x_api_key))
    host = result.scalar_one_or_none()
    if host is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="API key invalida")
    return host
