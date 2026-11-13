from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
from app.models.host import Host
from app.models.user import User
from app.services.auth import SESSION_COOKIE, read_session_token


class NotAuthenticated(Exception):
    """Sin sesion valida. El handler registrado en main.py decide si eso
    es un 401 JSON (API) o un redirect a /login (paginas)."""


class Forbidden(Exception):
    """Sesion valida pero el rol no alcanza (ej. viewer en algo de admin)."""


async def get_current_user(request: Request, db: AsyncSession = Depends(get_db)) -> User:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        raise NotAuthenticated()

    data = read_session_token(token)
    if not data:
        raise NotAuthenticated()

    user = await db.get(User, data["user_id"])
    if user is None or not user.active:
        raise NotAuthenticated()

    return user


async def require_admin(user: User = Depends(get_current_user)) -> User:
    if user.role != "admin":
        raise Forbidden()
    return user


async def get_current_host(
    x_api_key: str = Header(default=""),
    db: AsyncSession = Depends(get_db),
) -> Host:
    result = await db.execute(select(Host).where(Host.api_key == x_api_key))
    host = result.scalar_one_or_none()
    if host is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="API key invalida")
    return host
