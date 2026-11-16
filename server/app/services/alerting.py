import asyncio
import logging

from sqlalchemy import select

from app.core.config import settings
from app.core.db import SessionLocal
from app.models.alert import Alert, AlertRule
from app.models.host import Host
from app.models.metric import Metric
from app.models.system_report import SystemReport
from app.services import ai, notify

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


def _fmt(value, unit: str = "") -> str:
    return "?" if value is None else f"{value:.1f}{unit}"


def _metric_snapshot(metric: Metric, cpu_count: int | None) -> str:
    """Las demas metricas del mismo momento: solo con "cpu_percent = 95"
    el modelo responde generico ("aumentar RAM o procesadores"). Con el
    contexto puede distinguir, p. ej., carga alta por iowait (disco) de CPU
    saturada, o memoria "usada" que en realidad es cache."""
    parts = [
        f"CPU {_fmt(metric.cpu_percent, '%')} (usuario {_fmt(metric.cpu_user_percent, '%')}, "
        f"sistema {_fmt(metric.cpu_system_percent, '%')}, iowait {_fmt(metric.cpu_iowait_percent, '%')}, "
        f"steal {_fmt(metric.cpu_steal_percent, '%')})",
        f"load {_fmt(metric.load1)}/{_fmt(metric.load5)}/{_fmt(metric.load15)} (1/5/15 min)"
        + (f" con {cpu_count} CPUs" if cpu_count else ""),
        f"memoria {_fmt(metric.mem_percent, '%')} ({_fmt(metric.mem_available_mb, ' MB')} disponibles de "
        f"{_fmt(metric.mem_total_mb, ' MB')}, {_fmt(metric.mem_cached_mb, ' MB')} en cache)",
        f"swap {_fmt(metric.swap_percent, '%')}",
        f"disco {_fmt(metric.disk_percent, '%')} ({_fmt(metric.disk_used_gb, ' GB')} de {_fmt(metric.disk_total_gb, ' GB')})",
    ]
    return "; ".join(parts)


async def _cpu_count(session, host_id) -> int | None:
    report = (
        await session.execute(select(SystemReport).where(SystemReport.host_id == host_id))
    ).scalar_one_or_none()
    return (report.raw or {}).get("cpu_count") if report else None


async def _generate_summary(host: Host, rule: AlertRule, value: float, snapshot: str) -> str | None:
    prompt = (
        f"El host '{host.name}' ({host.hostname}) disparó la alerta '{rule.name}': "
        f"{rule.metric_field} = {value:.2f} (umbral {rule.operator} {rule.threshold}, severidad {rule.severity}). "
        f"Metricas del mismo momento: {snapshot}. "
        "Explica en 2-3 frases la causa probable segun estas metricas y una acción recomendada. "
        "No inventes procesos ni datos que no te di."
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
                    notify.notify_later(
                        f"alert|{host.id}|{rule.id}", rule.severity,
                        f"Prox Secure · {str(rule.severity).upper()} · {host.name}: {rule.name}",
                        f"{rule.metric_field} = {value:.1f} (umbral {rule.operator} {rule.threshold}) en {host.name}.",
                    )
                    snapshot = _metric_snapshot(metric, await _cpu_count(session, host.id))
                    summary = await _generate_summary(host, rule, value, snapshot)
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
