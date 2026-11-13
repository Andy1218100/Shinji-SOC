import asyncio
import logging

from sqlalchemy import select

from app.core.config import settings
from app.core.db import SessionLocal
from app.models.alert import Alert, AlertRule
from app.models.host import Host
from app.models.metric import Metric
from app.services import ai

logger = logging.getLogger("alerting")

_OPS = {
    ">": lambda v, t: v > t,
    "<": lambda v, t: v < t,
    ">=": lambda v, t: v >= t,
    "<=": lambda v, t: v <= t,
}


async def _latest_metric(session, host_id) -> Metric | None:
    result = await session.execute(
        select(Metric).where(Metric.host_id == host_id).order_by(Metric.ts.desc()).limit(1)
    )
    return result.scalar_one_or_none()


async def _hosts_for_rule(session, rule: AlertRule) -> list[Host]:
    if rule.host_id:
        result = await session.execute(select(Host).where(Host.id == rule.host_id))
        host = result.scalar_one_or_none()
        return [host] if host else []
    result = await session.execute(select(Host))
    return list(result.scalars().all())


async def _open_alert(session, rule_id, host_id) -> Alert | None:
    result = await session.execute(
        select(Alert).where(Alert.rule_id == rule_id, Alert.host_id == host_id, Alert.status == "firing")
    )
    return result.scalar_one_or_none()


async def _generate_summary(host: Host, rule: AlertRule, value: float) -> str | None:
    prompt = (
        f"El host '{host.name}' ({host.hostname}) disparó la alerta '{rule.name}': "
        f"{rule.metric_field} = {value:.2f} (umbral {rule.operator} {rule.threshold}, severidad {rule.severity}). "
        "Explica en 2-3 frases la causa probable y una acción recomendada."
    )
    try:
        return await ai.ask(prompt)
    except Exception:
        logger.exception("No se pudo generar el resumen de IA para la alerta")
        return None


async def evaluate_once() -> None:
    async with SessionLocal() as session:
        rules = (await session.execute(select(AlertRule).where(AlertRule.enabled.is_(True)))).scalars().all()

        for rule in rules:
            op = _OPS.get(rule.operator)
            if op is None:
                continue

            for host in await _hosts_for_rule(session, rule):
                metric = await _latest_metric(session, host.id)
                if metric is None:
                    continue

                value = getattr(metric, rule.metric_field, None)
                if value is None:
                    continue

                existing = await _open_alert(session, rule.id, host.id)
                breached = op(value, rule.threshold)

                if breached and existing is None:
                    alert = Alert(rule_id=rule.id, host_id=host.id, value=value, status="firing")
                    session.add(alert)
                    await session.commit()
                    summary = await _generate_summary(host, rule, value)
                    if summary:
                        alert.ai_summary = summary
                        await session.commit()
                elif not breached and existing is not None:
                    from sqlalchemy import func

                    existing.status = "resolved"
                    existing.resolved_at = func.now()
                    await session.commit()


async def run_forever() -> None:
    while True:
        try:
            await evaluate_once()
        except Exception:
            logger.exception("Falló un ciclo de evaluación de alertas")
        await asyncio.sleep(settings.alert_eval_interval_seconds)
