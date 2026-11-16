"""Primera instalacion: crear la cuenta super admin desde la pagina /setup.

Mientras no exista ningun usuario, el servidor genera un codigo de
instalacion y lo escribe en su log. /setup lo pide: sin el, un panel
recien instalado y expuesto quedaria en manos del primero que entre a
/setup. Se obtiene con:  docker compose logs server | grep "Codigo de instalacion"
"""

import hmac
import logging
import secrets

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.user import User

logger = logging.getLogger("first_run")

PENDING_MAX_AGE_SECONDS = 900
MAX_WRONG_CODES = 10

_code: str | None = None
_wrong_attempts = 0


async def users_exist(session: AsyncSession) -> bool:
    return bool((await session.execute(select(func.count(User.id)))).scalar_one())


def _new_code() -> None:
    global _code, _wrong_attempts
    raw = secrets.token_hex(4).upper()
    _code = f"{raw[:4]}-{raw[4:]}"
    _wrong_attempts = 0
    logger.warning("=" * 60)
    logger.warning("Primera instalacion: no hay usuarios todavia.")
    logger.warning("Abri /setup en el navegador y usa este codigo de instalacion:")
    logger.warning("Codigo de instalacion: %s", _code)
    logger.warning("=" * 60)


async def on_startup(session: AsyncSession) -> None:
    """Sin usuarios: genera el codigo. Con usuarios pero sin super admin
    (instalaciones de antes de que existiera el rol): el admin mas antiguo,
    que es quien instalo la plataforma, pasa a ser super admin."""
    if not await users_exist(session):
        _new_code()
        return
    has_super = (await session.execute(select(User.id).where(User.role == "superadmin").limit(1))).scalar_one_or_none()
    if has_super:
        return
    oldest_admin = (
        await session.execute(
            select(User).where(User.role == "admin", User.active.is_(True)).order_by(User.created_at).limit(1)
        )
    ).scalar_one_or_none()
    if oldest_admin:
        oldest_admin.role = "superadmin"
        await session.commit()
        logger.warning("No habia super admin: %s (el admin mas antiguo) ahora es super admin", oldest_admin.username)


def check_code(code: str) -> bool:
    """Cada codigo equivocado cuenta; despues de MAX_WRONG_CODES se genera
    uno nuevo (en el log) para que no se pueda probar por fuerza bruta."""
    global _wrong_attempts
    if _code is None:
        return False
    if hmac.compare_digest(code.strip().upper(), _code):
        return True
    _wrong_attempts += 1
    if _wrong_attempts >= MAX_WRONG_CODES:
        logger.warning("Demasiados codigos de instalacion equivocados: se genera uno nuevo")
        _new_code()
    return False


def consume_code() -> None:
    global _code
    _code = None


def _serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(settings.session_secret_key, salt="first-run")


def issue_pending(username: str, password_hash: str, mfa_secret: str) -> str:
    return _serializer().dumps({"u": username, "p": password_hash, "s": mfa_secret})


def read_pending(token: str) -> dict | None:
    try:
        return _serializer().loads(token, max_age=PENDING_MAX_AGE_SECONDS)
    except (BadSignature, SignatureExpired):
        return None
