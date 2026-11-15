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


PROMPT_EXAMPLES = 5


async def _generate_recommendation(host: Host, package: InstalledPackage, findings: list[VulnerabilityFinding]) -> str | None:
    """Una recomendacion por paquete, no por CVE: un paquete con 100 CVEs
    se arregla con un solo "actualizar", y 1 llamada a un modelo en CPU
    tarda ~20s (por CVE eran horas en un host real)."""
    critical = [f for f in findings if f.severity == "critical"]
    examples = (critical + [f for f in findings if f.severity != "critical"])[:PROMPT_EXAMPLES]
    example_lines = "; ".join(f"{f.vuln_id}: {(f.summary or 'sin resumen')[:150]}" for f in examples)
    fixed = sorted({f.fixed_version for f in findings if f.fixed_version})
    with_fix = sum(1 for f in findings if f.fixed_version)

    prompt = (
        f"En el host '{host.name}' el paquete {package.name} {package.version} tiene "
        f"{len(findings)} vulnerabilidades conocidas segun OSV.dev, {len(critical)} de severidad alta o critica. "
        f"Algunas: {example_lines}. "
        + (
            f"{with_fix} de ellas tienen version corregida publicada (versiones: {', '.join(fixed[:3])}). "
            if fixed
            else "Ninguna tiene version corregida publicada todavia. "
        )
        + "Redacta en 2-3 frases que accion tomar (actualizar el paquete, o como "
        "mitigar si no hay parche). No inventes numeros de version ni datos que no te di."
    )
    try:
        return await ai.ask(prompt)
    except Exception:
        logger.exception("No se pudo generar la recomendacion de IA para %s", package.name)
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
    existing = {
        (f.package_name, f.vuln_id): f
        for f in (
            await session.execute(select(VulnerabilityFinding).where(VulnerabilityFinding.host_id == host.id))
        ).scalars().all()
    }
    still_present: set[tuple[str, str]] = set()

    for package, vuln_ids in zip(packages, results):
        if not vuln_ids:
            continue
        pkg_findings: list[VulnerabilityFinding] = []
        added = False

        for vuln_id in vuln_ids:
            key = (package.name, vuln_id)
            still_present.add(key)
            finding = existing.get(key)
            if finding:
                finding.last_seen = now
                finding.package_version = package.version
                if finding.status == "resolved":
                    finding.status = "open"
                pkg_findings.append(finding)
                continue

            try:
                vuln = await osv.get_vuln(vuln_id)
            except Exception:
                logger.exception("Fallo al pedir detalle de %s", vuln_id)
                continue

            finding = VulnerabilityFinding(
                host_id=host.id,
                package_name=package.name,
                package_version=package.version,
                vuln_id=vuln_id,
                summary=vuln.get("summary") or vuln.get("details", "")[:300],
                severity=osv.extract_severity(vuln),
                fixed_version=osv.extract_fixed_version(vuln, package.name, ecosystem),
                source_url=osv.extract_source_url(vuln),
            )
            session.add(finding)
            pkg_findings.append(finding)
            added = True
            new_findings += 1

        await session.commit()

        # Regenerar si cambio el conjunto de CVEs (nuevos o arreglados), si
        # fallo la IA la vez pasada (None) o si quedaron textos distintos de
        # cuando era una por CVE.
        dropped = any(
            name == package.name and vid not in vuln_ids and f.status != "resolved"
            for (name, vid), f in existing.items()
        )
        recs = {f.ai_recommendation for f in pkg_findings}
        if pkg_findings and (added or dropped or None in recs or len(recs) > 1):
            rec = await _generate_recommendation(host, package, pkg_findings)
            if rec:
                for f in pkg_findings:
                    f.ai_recommendation = rec
                await session.commit()

    # Lo que OSV ya no reporta para la version instalada ahora (paquete
    # actualizado o desinstalado) queda resuelto. Seguro de hacer aca: la
    # consulta a OSV de arriba fue completa o el escaneo ya habria salido.
    for key, finding in existing.items():
        if key not in still_present and finding.status != "resolved":
            finding.status = "resolved"
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
