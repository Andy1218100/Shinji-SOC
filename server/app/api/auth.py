from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.core.config import settings
from app.core.db import get_db
from app.models.user import User
from app.schemas.auth import LoginRequest, LoginResponse, MeResponse, MfaVerifyRequest, SetupRequest
from app.services import auth

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])

GENERIC_LOGIN_ERROR = "Usuario o contrasena invalidos"
MIN_PASSWORD_LENGTH = 10


def _set_session_cookie(response: Response, user: User) -> None:
    token = auth.issue_session_token(str(user.id), user.role)
    response.set_cookie(
        auth.SESSION_COOKIE,
        token,
        max_age=settings.session_max_age_seconds,
        httponly=True,
        samesite="lax",
        secure=settings.session_cookie_secure,
        path="/",
    )


def _is_locked(user: User) -> bool:
    return bool(user.locked_until and user.locked_until > datetime.now(timezone.utc))


async def _register_failure(db: AsyncSession, user: User) -> None:
    user.failed_attempts += 1
    if user.failed_attempts >= settings.login_max_attempts:
        user.locked_until = datetime.now(timezone.utc) + timedelta(seconds=settings.login_lockout_seconds)
        user.failed_attempts = 0
    await db.commit()


async def _register_success(db: AsyncSession, user: User) -> None:
    user.failed_attempts = 0
    user.locked_until = None
    user.last_login = datetime.now(timezone.utc)
    await db.commit()


@router.post("/login", response_model=LoginResponse)
async def login(payload: LoginRequest, db: AsyncSession = Depends(get_db)):
    user = (await db.execute(select(User).where(User.username == payload.username))).scalar_one_or_none()

    # Mismo mensaje generico exista o no el usuario, para no confirmar usernames.
    if user is None or not user.active:
        raise HTTPException(status_code=401, detail=GENERIC_LOGIN_ERROR)

    if _is_locked(user):
        raise HTTPException(status_code=423, detail="Cuenta bloqueada temporalmente por varios intentos fallidos")

    if not auth.verify_password(payload.password, user.password_hash):
        await _register_failure(db, user)
        raise HTTPException(status_code=401, detail=GENERIC_LOGIN_ERROR)

    if user.must_set_password or not user.mfa_enabled:
        pending = auth.issue_pending_token(str(user.id), "setup")
        return LoginResponse(
            stage="setup",
            pending_token=pending,
            otpauth_uri=auth.totp_uri(user.username, user.mfa_secret),
            mfa_secret=user.mfa_secret,
        )

    pending = auth.issue_pending_token(str(user.id), "mfa")
    return LoginResponse(stage="mfa", pending_token=pending)


@router.post("/setup")
async def complete_setup(payload: SetupRequest, response: Response, db: AsyncSession = Depends(get_db)):
    user_id = auth.read_pending_token(payload.pending_token, "setup")
    if not user_id:
        raise HTTPException(status_code=401, detail="Sesion de login expirada, inicia sesion de nuevo")

    user = await db.get(User, user_id)
    if user is None or not user.active:
        raise HTTPException(status_code=401, detail="Sesion de login expirada, inicia sesion de nuevo")

    if len(payload.new_password) < MIN_PASSWORD_LENGTH:
        raise HTTPException(status_code=422, detail=f"La contrasena debe tener al menos {MIN_PASSWORD_LENGTH} caracteres")

    if not auth.verify_totp(user.mfa_secret, payload.mfa_code):
        await _register_failure(db, user)
        raise HTTPException(status_code=401, detail="Codigo MFA invalido")

    user.password_hash = auth.hash_password(payload.new_password)
    user.must_set_password = False
    user.mfa_enabled = True
    await _register_success(db, user)

    _set_session_cookie(response, user)
    return {"status": "ok"}


@router.post("/mfa/verify")
async def verify_mfa(payload: MfaVerifyRequest, response: Response, db: AsyncSession = Depends(get_db)):
    user_id = auth.read_pending_token(payload.pending_token, "mfa")
    if not user_id:
        raise HTTPException(status_code=401, detail="Sesion de login expirada, inicia sesion de nuevo")

    user = await db.get(User, user_id)
    if user is None or not user.active:
        raise HTTPException(status_code=401, detail="Sesion de login expirada, inicia sesion de nuevo")

    if _is_locked(user):
        raise HTTPException(status_code=423, detail="Cuenta bloqueada temporalmente por varios intentos fallidos")

    if not auth.verify_totp(user.mfa_secret, payload.code):
        await _register_failure(db, user)
        raise HTTPException(status_code=401, detail="Codigo MFA invalido")

    await _register_success(db, user)
    _set_session_cookie(response, user)
    return {"status": "ok"}


@router.post("/logout")
async def logout(response: Response):
    response.delete_cookie(auth.SESSION_COOKIE, path="/")
    return {"status": "ok"}


@router.get("/me", response_model=MeResponse)
async def me(user: User = Depends(get_current_user)):
    return MeResponse(id=str(user.id), username=user.username, role=user.role)
