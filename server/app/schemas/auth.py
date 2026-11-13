from pydantic import BaseModel

from app.schemas.common import UUIDStr


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    stage: str  # "setup" | "mfa"
    pending_token: str
    otpauth_uri: str | None = None  # solo en "setup"
    mfa_secret: str | None = None  # solo en "setup", respaldo para carga manual


class SetupRequest(BaseModel):
    pending_token: str
    new_password: str
    mfa_code: str


class MfaVerifyRequest(BaseModel):
    pending_token: str
    code: str


class MeResponse(BaseModel):
    id: UUIDStr
    username: str
    role: str
