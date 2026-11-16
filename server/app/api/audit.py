import hmac

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.db import get_db
from app.services import audit

router = APIRouter(prefix="/api/v1/audit", tags=["audit"])


async def require_audit_token(x_audit_token: str = Header(default="")) -> None:
    if not settings.audit_api_token:
        raise HTTPException(status_code=403, detail="Auditoria externa desactivada (falta AUDIT_API_TOKEN)")
    if not hmac.compare_digest(x_audit_token, settings.audit_api_token):
        raise HTTPException(status_code=401, detail="Token de auditoria invalido")


class AuditItem(BaseModel):
    id: str = Field(max_length=300)
    verdict: str = Field(pattern="^(ok|fix)$")
    corrected_recommendation: str | None = Field(default=None, max_length=2000)
    note: str | None = Field(default=None, max_length=1000)


class AuditRule(BaseModel):
    rule: str = Field(max_length=1000)
    # ambito: vulnerabilidades (por defecto), eventos o informes. package /
    # sobre: paquete o tipo de evento puntual (opcional).
    ambito: str | None = Field(default=None, max_length=32)
    package: str | None = Field(default=None, max_length=255)
    sobre: str | None = Field(default=None, max_length=255)


class AuditFeedback(BaseModel):
    items: list[AuditItem] = Field(default_factory=list, max_length=100)
    rules: list[AuditRule] = Field(default_factory=list, max_length=50)


@router.get("/report", dependencies=[Depends(require_audit_token)])
async def get_report(
    limit: int = Query(default=audit.REPORT_DEFAULT_LIMIT, ge=1, le=100),
    tipo: str = Query(default="vulnerabilidades", pattern="^(vulnerabilidades|eventos|informes)$"),
    db: AsyncSession = Depends(get_db),
):
    return await audit.build_report(db, limit, tipo)


@router.post("/feedback", dependencies=[Depends(require_audit_token)])
async def post_feedback(payload: AuditFeedback, db: AsyncSession = Depends(get_db)):
    return await audit.apply_feedback(
        db, [i.model_dump() for i in payload.items], [r.model_dump() for r in payload.rules]
    )
