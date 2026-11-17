"""Codigos de respaldo del MFA: 10 por cuenta, de un solo uso.

Sirven para entrar cuando no se tiene el telefono (perdido, roto, cambiado
sin pasar la app). Se generan al enrolar el MFA y desde Mi cuenta; generar
codigos nuevos invalida los anteriores. Solo reemplazan al codigo de 6
digitos en el login: las acciones sensibles (guardar configuracion, borrar
un host) siguen pidiendo el codigo de la app.
"""

from datetime import datetime, timezone

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import MfaRecoveryCode, User
from app.services import auth


async def replace_codes(db: AsyncSession, user: User) -> list[str]:
    """Borra los codigos de la cuenta y crea 10 nuevos. Devuelve el texto,
    que no se vuelve a poder leer. No hace commit."""
    await db.execute(delete(MfaRecoveryCode).where(MfaRecoveryCode.user_id == user.id))
    codes = auth.generate_recovery_codes()
    for code in codes:
        db.add(MfaRecoveryCode(user_id=user.id, code_hash=auth.hash_password(auth.normalize_recovery_code(code))))
    return codes


async def delete_codes(db: AsyncSession, user: User) -> None:
    await db.execute(delete(MfaRecoveryCode).where(MfaRecoveryCode.user_id == user.id))


async def use_code(db: AsyncSession, user: User, code: str) -> bool:
    """Si `code` es uno de los codigos sin usar de la cuenta, lo marca usado.
    No hace commit."""
    normalized = auth.normalize_recovery_code(code)
    if normalized is None:
        return False
    unused = (await db.execute(select(MfaRecoveryCode).where(
        MfaRecoveryCode.user_id == user.id, MfaRecoveryCode.used_at.is_(None)))).scalars().all()
    for row in unused:
        if auth.verify_password(normalized, row.code_hash):
            row.used_at = datetime.now(timezone.utc)
            return True
    return False


async def counts(db: AsyncSession, user_id) -> tuple[int, int]:
    """(sin usar, total) de la cuenta."""
    total, left = (await db.execute(select(
        func.count(MfaRecoveryCode.id),
        func.count(MfaRecoveryCode.id).filter(MfaRecoveryCode.used_at.is_(None)),
    ).where(MfaRecoveryCode.user_id == user_id))).one()
    return left, total
