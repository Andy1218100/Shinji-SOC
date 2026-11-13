from datetime import datetime

from pydantic import BaseModel

from app.schemas.common import UUIDStr


class SecurityEventOut(BaseModel):
    id: UUIDStr
    host_id: UUIDStr
    kind: str
    severity: str
    source_ip: str | None
    detail: dict
    suggested_action: str | None
    status: str
    ai_summary: str | None
    geo_country: str | None
    geo_city: str | None
    geo_lat: float | None
    geo_lon: float | None
    created_at: datetime

    class Config:
        from_attributes = True


class CommandOut(BaseModel):
    id: UUIDStr
    host_id: UUIDStr
    action: str
    payload: dict
    status: str

    class Config:
        from_attributes = True


class CommandResultIn(BaseModel):
    status: str  # done | failed
    result: str | None = None


class BlockedIPOut(BaseModel):
    id: UUIDStr
    host_id: UUIDStr
    ip: str
    reason: str | None
    blocked_at: datetime
    unblocked_at: datetime | None

    class Config:
        from_attributes = True
