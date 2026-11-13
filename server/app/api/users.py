from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_admin
from app.core.db import get_db
from app.models.user import User
from app.schemas.user import UserCreate, UserCreated, UserOut
from app.services import auth

router = APIRouter(prefix="/api/v1/users", tags=["users"])


@router.get("", response_model=list[UserOut])
async def list_users(db: AsyncSession = Depends(get_db), _: User = Depends(require_admin)):
    result = await db.execute(select(User).order_by(User.username))
    return [UserOut.model_validate(u) for u in result.scalars().all()]


@router.post("", response_model=UserCreated)
async def create_user(
    payload: UserCreate,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    existing = (await db.execute(select(User).where(User.username == payload.username))).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=409, detail="Ese nombre de usuario ya existe")

    temp_password = auth.generate_temp_password()
    user = User(
        username=payload.username,
        role=payload.role,
        password_hash=auth.hash_password(temp_password),
        mfa_secret=auth.generate_mfa_secret(),
        mfa_enabled=False,
        must_set_password=True,
        created_by=admin.id,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    return UserCreated(
        id=str(user.id),
        username=user.username,
        role=user.role,
        active=user.active,
        mfa_enabled=user.mfa_enabled,
        must_set_password=user.must_set_password,
        created_at=user.created_at,
        last_login=user.last_login,
        temporary_password=temp_password,
    )


@router.post("/{user_id}/deactivate")
async def deactivate_user(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    if user_id == str(admin.id):
        raise HTTPException(status_code=400, detail="No podes desactivar tu propia cuenta")
    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="No encontrado")
    user.active = False
    await db.commit()
    return {"status": "ok"}


@router.post("/{user_id}/reactivate")
async def reactivate_user(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin),
):
    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="No encontrado")
    user.active = True
    await db.commit()
    return {"status": "ok"}


@router.post("/{user_id}/reset-password", response_model=UserCreated)
async def reset_password(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin),
):
    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="No encontrado")

    temp_password = auth.generate_temp_password()
    user.password_hash = auth.hash_password(temp_password)
    user.must_set_password = True
    user.failed_attempts = 0
    user.locked_until = None
    await db.commit()

    return UserCreated(
        id=str(user.id),
        username=user.username,
        role=user.role,
        active=user.active,
        mfa_enabled=user.mfa_enabled,
        must_set_password=user.must_set_password,
        created_at=user.created_at,
        last_login=user.last_login,
        temporary_password=temp_password,
    )
