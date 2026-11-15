import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.host import Host
from app.models.system_report import SystemReport
from app.schemas.logs import SystemReportIn
from app.services import ai

logger = logging.getLogger("system_report")


def _join_capped(items: list[str], limit: int, empty: str) -> str:
    """Corta listas largas antes de mandarlas a la IA. Un host real puede
    tener decenas de logs (ej. debug logs de ifupdown2 con timestamp en el
    nombre, uno por cada vez que cambio la red) -- meter los 40 enteros en
    el prompt no le suma nada util al resumen y en la practica hizo que el
    modelo chico (qwen2.5:3b en CPU) tardara mas de los 120s de timeout,
    dejando el intento de resumen simplemente fallido."""
    if not items:
        return empty
    shown = ", ".join(items[:limit])
    extra = len(items) - limit
    return f"{shown} (y {extra} mas)" if extra > 0 else shown


def _build_prompt(host: Host, payload: SystemReportIn) -> str:
    lines = [
        f"Host: {host.name} ({host.hostname}).",
        f"Sistema operativo: {payload.os_name or 'desconocido'}"
        + (f" (kernel {payload.kernel})" if payload.kernel else "") + ".",
    ]
    if payload.cpu_count or payload.mem_total_mb or payload.disk_total_gb:
        lines.append(
            "Hardware: "
            + (f"{payload.cpu_count} CPUs, " if payload.cpu_count else "")
            + (f"{payload.mem_total_mb:.0f} MB de RAM, " if payload.mem_total_mb else "")
            + (f"{payload.disk_total_gb:.0f} GB de disco." if payload.disk_total_gb else "")
        )
    lines.append(
        "Servicios detectados corriendo: "
        + _join_capped(payload.services, 15, "ninguno reconocido") + "."
    )
    if payload.listening_ports:
        ports = [f"{p.port}" + (f" ({p.process})" if p.process else "") for p in payload.listening_ports]
        lines.append(f"Puertos en escucha ({len(ports)} en total): {_join_capped(ports, 20, '')}.")
    lines.append(
        f"Logs que el agente va a vigilar ({len(payload.log_paths)} en total): "
        + _join_capped(payload.log_paths, 10, "ninguno encontrado") + "."
    )
    lines.append(
        "Cuentas de servicio que el agente va a vigilar por posible webshell/RCE: "
        + _join_capped(payload.service_accounts, 15, "ninguna encontrada") + "."
    )

    return (
        "Sos un asistente de seguridad de infraestructura. A partir de estos datos reales "
        "de un servidor recien conectado, escribi un informe breve (4-6 frases, en espanol) "
        "que explique que tipo de servidor parece ser, que deberia vigilar el administrador, "
        "y si algo te llama la atencion (puertos abiertos no habituales, falta de logs para "
        "vigilar, etc.). No inventes datos que no te di; si falta informacion, decilo.\n\n"
        + "\n".join(lines)
    )


async def save_and_summarize(db: AsyncSession, host: Host, payload: SystemReportIn) -> SystemReport:
    report = (
        await db.execute(select(SystemReport).where(SystemReport.host_id == host.id))
    ).scalar_one_or_none()
    if report is None:
        report = SystemReport(host_id=host.id)
        db.add(report)

    report.raw = payload.model_dump()
    await db.commit()
    await db.refresh(report)

    try:
        report.ai_summary = await ai.ask(_build_prompt(host, payload))
    except Exception:
        # No dejar el resumen de un escaneo anterior mostrado como si fuera
        # vigente -- mejor mostrar "no se pudo generar" (ver host.html) que
        # un texto desactualizado y potencialmente ya incorrecto.
        logger.exception("No se pudo generar el informe de IA para %s", host.name)
        report.ai_summary = None
    await db.commit()

    return report
