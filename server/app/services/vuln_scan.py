import asyncio
import logging
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.db import SessionLocal
from app.models.host import Host
from app.models.vulnerability import InstalledPackage, VulnerabilityFinding
from app.services import ai, osv

logger = logging.getLogger("vuln_scan")


async def _generate_recommendation(host: Host, finding_facts: dict) -> str | None:
    prompt = (
        f"En el host '{host.name}' el paquete {finding_facts['package']} "
        f"{finding_facts['version']} tiene la vulnerabilidad conocida "
        f"{finding_facts['vuln_id']}: {finding_facts['summary'] or '(sin resumen disponible)'}. "
        + (
            f"Hay una version corregida disponible: {finding_facts['fixed_version']}. "
            if finding_facts.get("fixed_version")
            else "No hay version corregida publicada todavia. "
        )
        + "Redacta en 2-3 frases que accion tomar (actualizar a que version, o como "
        "mitigar si no hay parche). No inventes datos que no te di."
    )
    try:
        return await ai.ask(prompt)
    except Exception:
        logger.exception("No se pudo generar la recomendacion de IA para %s", finding_facts["vuln_id"])
        return None


async def scan_host(session: AsyncSession, host: Host) -> int:
    packages = (
        await session.execute(select(InstalledPackage).where(InstalledPackage.host_id == host.id))
    ).scalars().all()
    if not packages:
        return 0

    pairs = [(p.name, p.version) for p in packages]
    # OSV.dev versiona el ecosistema Debian por release (Debian:11,
    # Debian:12, ...). Sin el numero de release, las comparaciones de
    # version salen mal (puede marcar como vulnerable algo ya parchado
    # en bullseye porque el fix oficial es de bookworm). Si el agente
    # todavia no reporto su release, no escaneamos ese host en vez de
    # arriesgar falsos positivos/negativos.
    if not host.debian_release:
        logger.info("Host %s sin debian_release reportado todavia, salteando escaneo", host.name)
        return 0
    ecosystem = f"Debian:{host.debian_release}"

    try:
        results = await osv.query_batch(pairs, ecosystem=ecosystem)
    except Exception:
        logger.exception("Fallo la consulta a OSV.dev para %s", host.name)
        return 0

    new_findings = 0
    now = datetime.now(timezone.utc)

    for package, vuln_ids in zip(packages, results):
        for vuln_id in vuln_ids:
            existing = (
                await session.execute(
                    select(VulnerabilityFinding).where(
                        VulnerabilityFinding.host_id == host.id,
                        VulnerabilityFinding.package_name == package.name,
                        VulnerabilityFinding.vuln_id == vuln_id,
                    )
                )
            ).scalar_one_or_none()

            if existing:
                existing.last_seen = now
                continue

            try:
                vuln = await osv.get_vuln(vuln_id)
            except Exception:
                logger.exception("Fallo al pedir detalle de %s", vuln_id)
                continue

            facts = {
                "package": package.name,
                "version": package.version,
                "vuln_id": vuln_id,
                "summary": vuln.get("summary") or vuln.get("details", "")[:300],
                "fixed_version": osv.extract_fixed_version(vuln, package.name),
            }

            finding = VulnerabilityFinding(
                host_id=host.id,
                package_name=package.name,
                package_version=package.version,
                vuln_id=vuln_id,
                summary=facts["summary"],
                severity=osv.extract_severity(vuln),
                fixed_version=facts["fixed_version"],
                source_url=osv.extract_source_url(vuln),
            )
            session.add(finding)
            await session.commit()

            finding.ai_recommendation = await _generate_recommendation(host, facts)
            await session.commit()
            new_findings += 1

    await session.commit()
    return new_findings


async def scan_all_hosts() -> None:
    async with SessionLocal() as session:
        hosts = (await session.execute(select(Host))).scalars().all()
        for host in hosts:
            try:
                found = await scan_host(session, host)
                if found:
                    logger.info("Host %s: %d vulnerabilidades nuevas", host.name, found)
            except Exception:
                logger.exception("Fallo el escaneo de vulnerabilidades para %s", host.name)


async def run_forever() -> None:
    while True:
        try:
            await scan_all_hosts()
        except Exception:
            logger.exception("Fallo un ciclo de escaneo de vulnerabilidades")
        await asyncio.sleep(settings.vuln_scan_interval_seconds)
