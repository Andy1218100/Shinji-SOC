import re

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth import MIN_PASSWORD_LENGTH, _set_session_cookie
from app.core.db import get_db
from app.models.user import User
from app.services import auth, first_run

router = APIRouter(prefix="/api/v1/setup", tags=["setup"])

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.-]{3,64}$")


class SetupBegin(BaseModel):
    code: str = Field(max_length=20)
    username: str = Field(max_length=64)
    password: str = Field(max_length=256)


class SetupFinish(BaseModel):
    pending_token: str = Field(max_length=2000)
    mfa_code: str = Field(min_length=6, max_length=8)


async def _require_no_users(db: AsyncSession) -> None:
    if await first_run.users_exist(db):
        raise HTTPException(status_code=409, detail="La plataforma ya tiene usuarios: inicia sesion en /login")


@router.get("/status")
async def setup_status(db: AsyncSession = Depends(get_db)):
    return {"needed": not await first_run.users_exist(db)}


@router.post("/begin")
async def setup_begin(payload: SetupBegin, db: AsyncSession = Depends(get_db)):
    await _require_no_users(db)
    if not first_run.check_code(payload.code):
        raise HTTPException(status_code=401, detail="Codigo de instalacion incorrecto (esta en el log del servidor)")
    if not USERNAME_RE.match(payload.username):
        raise HTTPException(status_code=422, detail="Usuario: 3 a 64 caracteres, solo letras, numeros, punto, guion y guion bajo")
    if len(payload.password) < MIN_PASSWORD_LENGTH:
        raise HTTPException(status_code=422, detail=f"La contrasena debe tener al menos {MIN_PASSWORD_LENGTH} caracteres")
    secret = auth.generate_mfa_secret()
    # El usuario no se crea hasta confirmar el MFA: si se abandona a mitad
    # de camino, no queda una cuenta super admin sin segundo factor.
    token = first_run.issue_pending(payload.username, auth.hash_password(payload.password), secret)
    return {
        "pending_token": token,
        "otpauth_uri": auth.totp_uri(payload.username, secret),
        "mfa_secret": secret,
    }


@router.post("/finish")
async def setup_finish(payload: SetupFinish, response: Response, db: AsyncSession = Depends(get_db)):
    await _require_no_users(db)
    data = first_run.read_pending(payload.pending_token)
    if not data:
        raise HTTPException(status_code=401, detail="La configuracion expiro (15 minutos): empieza de nuevo")
    if not auth.verify_totp(data["s"], payload.mfa_code):
        raise HTTPException(status_code=401, detail="Codigo MFA invalido: revisa la hora del telefono")
    user = User(
        username=data["u"],
        role="superadmin",
        password_hash=data["p"],
        mfa_secret=data["s"],
        mfa_enabled=True,
        must_set_password=False,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    first_run.consume_code()
    _set_session_cookie(response, user)
    return {"status": "ok"}
