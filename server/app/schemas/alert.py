from datetime import datetime

from pydantic import BaseModel

from app.schemas.common import UUIDStr


class AlertRuleCreate(BaseModel):
    host_id: str | None = None
    name: str
    metric_field: str
    operator: str
    threshold: float
    duration_seconds: int = 0
    severity: str = "warning"
    enabled: bool = True


class AlertRuleOut(AlertRuleCreate):
    id: UUIDStr
    host_id: UUIDStr | None = None

    class Config:
        from_attributes = True


class AlertOut(BaseModel):
    id: UUIDStr
    rule_id: UUIDStr
    host_id: UUIDStr
    value: float
    status: str
    triggered_at: datetime
    resolved_at: datetime | None
    ai_summary: str | None

    class Config:
        from_attributes = True


class AskRequest(BaseModel):
    question: str
    host_id: str | None = None
    backend: str | None = None  # "ollama" | "claude"
