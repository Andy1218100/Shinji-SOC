from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_admin
from app.core.db import get_db
from app.models.alert import Alert, AlertRule
from app.schemas.alert import AlertOut, AlertRuleCreate, AlertRuleOut

router = APIRouter(prefix="/api/v1", tags=["alerts"])


@router.post("/alert-rules", response_model=AlertRuleOut, dependencies=[Depends(require_admin)])
async def create_rule(payload: AlertRuleCreate, db: AsyncSession = Depends(get_db)):
    rule = AlertRule(**payload.model_dump())
    db.add(rule)
    await db.commit()
    await db.refresh(rule)
    return AlertRuleOut.model_validate(rule)


@router.get("/alert-rules", response_model=list[AlertRuleOut], dependencies=[Depends(get_current_user)])
async def list_rules(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(AlertRule))
    return [AlertRuleOut.model_validate(r) for r in result.scalars().all()]


@router.get("/alerts", response_model=list[AlertOut], dependencies=[Depends(get_current_user)])
async def list_alerts(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Alert).order_by(Alert.triggered_at.desc()).limit(200))
    return [AlertOut.model_validate(a) for a in result.scalars().all()]
