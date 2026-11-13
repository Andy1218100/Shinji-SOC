from datetime import datetime

from pydantic import BaseModel, field_validator

from app.schemas.common import UUIDStr

VALID_ROLES = {"admin", "viewer"}


class UserCreate(BaseModel):
    username: str
    role: str = "viewer"

    @field_validator("role")
    @classmethod
    def role_valid(cls, v: str) -> str:
        if v not in VALID_ROLES:
            raise ValueError(f"role debe ser uno de {VALID_ROLES}")
        return v

    @field_validator("username")
    @classmethod
    def username_valid(cls, v: str) -> str:
        v = v.strip()
        if len(v) < 3:
            raise ValueError("el usuario debe tener al menos 3 caracteres")
        return v


class UserOut(BaseModel):
    id: UUIDStr
    username: str
    role: str
    active: bool
    mfa_enabled: bool
    must_set_password: bool
    created_at: datetime
    last_login: datetime | None

    class Config:
        from_attributes = True


class UserCreated(UserOut):
    temporary_password: str
