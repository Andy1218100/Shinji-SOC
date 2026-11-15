from datetime import datetime

from pydantic import BaseModel

from app.schemas.common import UUIDStr


class HostCreate(BaseModel):
    name: str
    hostname: str
    ip_address: str | None = None
    os: str | None = None


class HostOut(BaseModel):
    id: UUIDStr
    name: str
    hostname: str
    ip_address: str | None
    os: str | None
    last_seen: datetime | None
    geo_lat: float | None = None
    geo_lon: float | None = None

    class Config:
        from_attributes = True


class HostCreated(HostOut):
    api_key: str


class HostDeleteRequest(BaseModel):
    mfa_code: str


class GrantLogAccessRequest(BaseModel):
    mfa_code: str
    path: str
