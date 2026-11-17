"""Mi cuenta: estado del MFA, codigos de respaldo y cambio de telefono.

Cualquier rol puede usarla sobre su propia cuenta. Generar codigos nuevos
pide un codigo de la app; cambiar de telefono pide la contrasena (si se
perdio el telefono, no hay codigo de la app para dar) y despues un codigo
del telefono nuevo.
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth import _register_failure, _register_success
from app.api.deps import get_current_user
from app.core.db import get_db
from app.models.user import User
from app.services import auth, recovery

router = APIRouter(prefix="/api/v1/account", tags=["account"])


class MfaCode(BaseModel):
    mfa_code: str = Field(min_length=6, max_length=8)


class PasswordOnly(BaseModel):
    password: str = Field(max_length=256)


class MfaChangeFinish(BaseModel):
    pending_token: str = Field(max_length=2000)
    mfa_code: str = Field(min_length=6, max_length=8)


@router.get("")
async def account(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    left, total = await recovery.counts(db, user.id)
    return {
        "username": user.username,
        "role": user.role,
        "mfa_enabled": user.mfa_enabled,
        "recovery_codes_left": left,
        "recovery_codes_total": total,
    }


@router.post("/recovery-codes")
async def regenerate_recovery_codes(payload: MfaCode, user: User = Depends(get_current_user),
                                    db: AsyncSession = Depends(get_db)):
    if not auth.verify_totp(user.mfa_secret, payload.mfa_code):
        await _register_failure(db, user)
        raise HTTPException(status_code=401, detail="Codigo MFA invalido")
    codes = await recovery.replace_codes(db, user)
    await _register_success(db, user)
    return {"recovery_codes": codes}


@router.post("/mfa/begin")
async def mfa_change_begin(payload: PasswordOnly, user: User = Depends(get_current_user),
                           db: AsyncSession = Depends(get_db)):
    if not auth.verify_password(payload.password, user.password_hash):
        await _register_failure(db, user)
        raise HTTPException(status_code=401, detail="Contrasena incorrecta")
    secret = auth.generate_mfa_secret()
    return {
        "pending_token": auth.issue_mfa_change_token(str(user.id), secret),
        "otpauth_uri": auth.totp_uri(user.username, secret),
        "mfa_secret": secret,
    }


@router.post("/mfa/finish")
async def mfa_change_finish(payload: MfaChangeFinish, user: User = Depends(get_current_user),
                            db: AsyncSession = Depends(get_db)):
    secret = auth.read_mfa_change_token(payload.pending_token, str(user.id))
    if not secret:
        raise HTTPException(status_code=401, detail="Pasaron mas de 15 minutos: empieza de nuevo")
    if not auth.verify_totp(secret, payload.mfa_code):
        await _register_failure(db, user)
        raise HTTPException(status_code=401, detail="Codigo invalido: revisa que sea el del telefono nuevo y su hora")
    user.mfa_secret = secret
    user.mfa_enabled = True
    # Codigos nuevos con la clave nueva: los anteriores pueden estar junto
    # al telefono perdido.
    codes = await recovery.replace_codes(db, user)
    await _register_success(db, user)
    return {"recovery_codes": codes}
