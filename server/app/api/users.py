from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_admin
from app.core.db import get_db
from app.models.user import User
from app.schemas.user import UserCreate, UserCreated, UserOut
from app.services import auth

router = APIRouter(prefix="/api/v1/users", tags=["users"])


def _check_can_manage(actor: User, target: User) -> None:
    """superadmin > admin > viewer. La cuenta super admin no se toca desde el
    panel; las cuentas admin solo las gestiona el super admin."""
    if target.is_superadmin:
        raise HTTPException(status_code=403, detail="La cuenta super admin no se puede modificar desde el panel")
    if target.is_admin and not actor.is_superadmin:
        raise HTTPException(status_code=403, detail="Solo el super admin puede gestionar cuentas admin")


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
    if payload.role == "admin" and not admin.is_superadmin:
        raise HTTPException(status_code=403, detail="Solo el super admin puede crear cuentas admin")
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
    _check_can_manage(admin, user)
    user.active = False
    await db.commit()
    return {"status": "ok"}


@router.post("/{user_id}/reactivate")
async def reactivate_user(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="No encontrado")
    _check_can_manage(admin, user)
    user.active = True
    await db.commit()
    return {"status": "ok"}


@router.delete("/{user_id}")
async def delete_user(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    if user_id == str(admin.id):
        raise HTTPException(status_code=400, detail="No podes eliminar tu propia cuenta")
    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="No encontrado")
    _check_can_manage(admin, user)

    created_others = (
        await db.execute(select(User.id).where(User.created_by == user.id).limit(1))
    ).scalar_one_or_none()
    if created_others:
        raise HTTPException(
            status_code=409,
            detail="Esta cuenta creo otras cuentas y no se puede eliminar; desactivala en su lugar",
        )

    await db.delete(user)
    await db.commit()
    return {"status": "ok"}


@router.post("/{user_id}/reset-password", response_model=UserCreated)
async def reset_password(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="No encontrado")
    _check_can_manage(admin, user)

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
