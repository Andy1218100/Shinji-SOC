import asyncio
import logging
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.db import SessionLocal
from app.models.host import Host
from app.models.vulnerability import InstalledPackage, VulnerabilityFinding
from app.services import ai, audit, osv

logger = logging.getLogger("vuln_scan")


PROMPT_EXAMPLES = 5
# Reglas que dejo el auditor externo (ver services/audit.py), cargadas al
# empezar cada escaneo. Pocas y cortas: cada una alarga el prompt y en CPU
# eso son segundos por recomendacion.
MAX_GLOBAL_RULES = 5
MAX_PACKAGE_RULES = 3
_active_rules: list = []


FALLBACK_NOTE = "(Recomendacion generada sin IA: el modelo no dio una respuesta valida.)"
# Textos fijos para casos donde la IA no aporta y puede confundir. Terminan
# en una marca para reconocerlos al decidir si regenerar.
FIXED_NOTE = "(Recomendacion fija, sin IA.)"
_THIRD_PARTY_BUILD = re.compile(r"pve|proxmox", re.IGNORECASE)


def is_third_party_build(version: str) -> bool:
    """Paquetes compilados por Proxmox (frr 10.6.1-1+pve3, corosync
    3.2.0-pve1) con el mismo nombre que el de Debian. OSV evalua el paquete
    de Debian (frr 10.3 en trixie): un CVE "8.3 through 10.5.1" sale contra
    la 10.6.1 de Proxmox aunque probablemente no la afecte."""
    return bool(_THIRD_PARTY_BUILD.search(version))


@dataclass
class SourcePackage:
    """Paquete fuente de Debian con los binarios instalados que salen de el.
    OSV indexa los avisos de Debian por fuente: consultar por binario
    dejaba afuera, p. ej., todo OpenSSL (libssl3t64 -> 0 avisos, openssl ->
    294) y glibc (libc6)."""

    name: str
    version: str
    binaries: list[str] = field(default_factory=list)


def _version_lt(a: str, b: str) -> bool:
    try:
        return subprocess.run(["dpkg", "--compare-versions", a, "lt", b], timeout=5).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def group_by_source(packages: list[InstalledPackage]) -> list[SourcePackage]:
    groups: dict[str, SourcePackage] = {}
    for p in packages:
        # Agentes viejos no mandan el fuente: el binario hace de fuente.
        name = p.source_name or p.name
        version = p.source_version or p.version
        group = groups.get(name)
        if group is None:
            groups[name] = SourcePackage(name, version, [p.name])
            continue
        group.binaries.append(p.name)
        # Binarios del mismo fuente en versiones distintas (upgrade a medias):
        # se evalua la mas vieja, que es la que puede seguir vulnerable.
        if version != group.version and _version_lt(version, group.version):
            group.version = version
    return sorted(groups.values(), key=lambda g: g.name)


def _upgrade_command(package: SourcePackage) -> str:
    return f"apt install --only-upgrade {' '.join(sorted(package.binaries)[:8])}"


# Binarios del fuente "linux" que NO son un kernel: cabeceras para compilar
# programas y herramientas. En un Proxmox real solo estaba linux-libc-dev
# (el kernel en uso era proxmox-kernel, que OSV no cubre) y salian 294 CVEs
# del kernel de Debian que no aplican a unas cabeceras.
_KERNEL_NON_KERNEL_BINARIES = re.compile(r"^(linux-libc-dev|linux-headers-.*|linux-kbuild-.*|linux-base|linux-source.*|linux-doc.*|linux-perf.*|bpftool|usbip|hyperv-daemons)$")


def not_applicable_reason(package: SourcePackage) -> str | None:
    if package.name == "linux" and package.binaries and all(
        _KERNEL_NON_KERNEL_BINARIES.match(b) for b in package.binaries
    ):
        return (
            f"Solo estan instalados {', '.join(sorted(package.binaries))} (cabeceras/herramientas), no el "
            "kernel de Debian: estos CVEs son del kernel y no aplican al kernel que corre el host."
        )
    return None


def _relevant(findings: list[VulnerabilityFinding]) -> list[VulnerabilityFinding]:
    return [f for f in findings if f.urgency != osv.UNIMPORTANT]


def _fixed_recommendation(package: SourcePackage, findings: list[VulnerabilityFinding]) -> str | None:
    if reason := not_applicable_reason(package):
        return f"{reason} No requiere accion. {FIXED_NOTE}"
    if is_third_party_build(package.version):
        return (
            f"{package.name} {package.version} es un paquete compilado por Proxmox, no el de Debian. "
            "OSV compara contra el paquete de Debian, asi que "
            + ("este CVE puede" if len(findings) == 1 else f"estos {len(findings)} CVEs pueden")
            + " no aplicar "
            "a esta version: revisar los avisos de seguridad de Proxmox y mantenerlo actualizado con "
            f"apt desde su repositorio. {FIXED_NOTE}"
        )
    if not _relevant(findings):
        return (
            f"Debian clasifica {'este CVE' if len(findings) == 1 else f'los {len(findings)} CVEs'} de "
            f"{package.name} como \"unimportant\": no afecta al paquete de Debian, no tiene impacto practico, "
            "o el paquete no tiene soporte de seguridad. Debian no publica correccion ni lo sigue, por eso "
            f"figura para todas las versiones. No requiere accion. {FIXED_NOTE}"
        )
    return None


def _fixed_versions(findings: list[VulnerabilityFinding]) -> list[str]:
    return sorted({f.fixed_version for f in findings if f.fixed_version})


def _build_prompt(host: Host, package: SourcePackage, all_findings: list[VulnerabilityFinding]) -> str:
    # Los "unimportant" no van al prompt: son ruido para la recomendacion.
    findings = _relevant(all_findings) or all_findings
    ignored = len(all_findings) - len(findings)
    critical = [f for f in findings if f.severity == "critical"]
    examples = (critical + [f for f in findings if f.severity != "critical"])[:PROMPT_EXAMPLES]
    example_lines = "; ".join(f"{f.vuln_id}: {(f.summary or 'sin resumen')[:150]}" for f in examples)
    fixed = _fixed_versions(findings)
    with_fix = sum(1 for f in findings if f.fixed_version)

    if fixed:
        status = (
            f"{with_fix} de ellas tienen version corregida publicada (versiones: {', '.join(fixed[:3])}). "
            "Redacta en 2-3 frases la accion a tomar: actualizar el paquete con apt a una version corregida"
            + (", y que hacer con las que todavia no tienen parche." if with_fix < len(findings) else ".")
        )
    else:
        # Sin esta aclaracion el modelo responde casi siempre "actualizar a
        # la ultima version", que no corrige nada si no hay parche publicado.
        # Y si se le da "desinstalar" como ejemplo, lo recomienda para todo,
        # incluso apt o libgcrypt20 (paso en un host real).
        status = (
            "Ninguna tiene version corregida publicada todavia, asi que actualizar ahora no las corrige. "
            "Redacta en 2-3 frases como reducir el riesgo segun para que sirve este paquete, y que "
            "aplique la actualizacion de seguridad de Debian apenas se publique. No recomiendes "
            "desinstalar paquetes base del sistema (gestor de paquetes, shell, librerias del sistema)."
        )
    return (
        f"En el host '{host.name}' el paquete {package.name} {package.version}"
        + (f" (paquete fuente de Debian; instalado como {', '.join(sorted(package.binaries)[:6])})"
           if package.binaries != [package.name] else "")
        + " tiene "
        f"{len(findings)} vulnerabilidades conocidas segun OSV.dev, {len(critical)} de severidad alta o critica"
        + (f" (y otras {ignored} que Debian clasifica como sin importancia, que no hace falta tratar)" if ignored else "")
        + f". Algunas: {example_lines}. {status} No inventes numeros de version, CVEs ni datos que no te di."
        + _rules_text(package.name)
    )


def _rules_text(package_name: str) -> str:
    general = [r.rule for r in _active_rules if r.package_name is None][:MAX_GLOBAL_RULES]
    specific = [r.rule for r in _active_rules if r.package_name == package_name][:MAX_PACKAGE_RULES]
    rules = specific + general
    if not rules:
        return ""
    return " Reglas de un auditor que reviso respuestas anteriores (respetalas): " + " ".join(
        f"({i}) {r}" for i, r in enumerate(rules, start=1)
    )


def _grounding_source(prompt: str, findings: list[VulnerabilityFinding]) -> str:
    # Todo lo que el texto puede citar sin inventar: el prompt mas todos los
    # CVEs y versiones corregidas del paquete (el prompt solo lleva 5 ejemplos).
    return " ".join([prompt, *(f.vuln_id for f in findings), *_fixed_versions(findings)])


def _fallback_recommendation(package: SourcePackage, findings: list[VulnerabilityFinding]) -> str:
    fixed = _fixed_versions(findings)
    with_fix = sum(1 for f in findings if f.fixed_version)
    if fixed:
        return (
            f"Actualizar {package.name} con apt ({_upgrade_command(package)}): "
            f"{with_fix} de {len(findings)} vulnerabilidades tienen version corregida publicada "
            f"({', '.join(fixed[:3])}). {FALLBACK_NOTE}"
        )
    return (
        f"Ninguna de las {len(findings)} vulnerabilidades de {package.name} tiene version corregida "
        "publicada. Aplicar la actualizacion de seguridad de Debian apenas se publique (apt update && "
        f"apt upgrade) y limitar la exposicion de los servicios que usan el paquete. {FALLBACK_NOTE}"
    )


async def _generate_recommendation(host: Host, package: SourcePackage, findings: list[VulnerabilityFinding]) -> str | None:
    """Una recomendacion por paquete, no por CVE: un paquete con 100 CVEs
    se arregla con un solo "actualizar", y 1 llamada a un modelo en CPU
    tarda ~20s (por CVE eran horas en un host real)."""
    if fixed := _fixed_recommendation(package, findings):
        return fixed
    try:
        return await ai.ask(_build_prompt(host, package, findings), grounded=True)
    except ai.AIOutputError as exc:
        # Mejor una recomendacion fija correcta que nada. En el proximo
        # escaneo (diario) se vuelve a probar con la IA.
        logger.warning("IA invalida para %s, uso recomendacion fija: %s", package.name, exc)
        return _fallback_recommendation(package, findings)
    except Exception:
        logger.exception("No se pudo generar la recomendacion de IA para %s", package.name)
        return None


def _needs_new_recommendation(host: Host, package: SourcePackage, findings: list[VulnerabilityFinding]) -> bool:
    recs = {f.ai_recommendation for f in findings}
    # None: la IA no respondio la vez pasada. Mas de un texto: quedaron de
    # cuando era una por CVE.
    if None in recs or len(recs) > 1:
        return True
    rec = next(iter(recs))
    if any(f.rec_source == "claude" for f in findings):
        # Corregida por el auditor: se respeta hasta que cambien los CVEs.
        return False
    fixed = _fixed_recommendation(package, findings)
    if fixed is not None:
        return rec != fixed
    if rec.endswith(FALLBACK_NOTE) or rec.endswith(FIXED_NOTE):
        return True
    # Texto guardado antes de que existieran estas validaciones.
    source = _grounding_source(_build_prompt(host, package, findings), findings)
    return ai.looks_degenerate(rec) or bool(ai.ungrounded_identifiers(rec, source))


async def scan_host(session: AsyncSession, host: Host) -> int:
    packages = (
        await session.execute(select(InstalledPackage).where(InstalledPackage.host_id == host.id))
    ).scalars().all()
    if not packages:
        return 0

    sources = group_by_source(list(packages))
    pairs = [(src.name, src.version) for src in sources]
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

    _active_rules[:] = await audit.active_rules(session)
    new_findings = 0
    now = datetime.now(timezone.utc)
    existing = {
        (f.package_name, f.vuln_id): f
        for f in (
            await session.execute(select(VulnerabilityFinding).where(VulnerabilityFinding.host_id == host.id))
        ).scalars().all()
    }
    still_present: set[tuple[str, str]] = set()

    for package, vuln_ids in zip(sources, results):
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
                finding.not_applicable = not_applicable_reason(package)
                if finding.status == "resolved":
                    finding.status = "open"
                    finding.resolved_at = None
                    finding.resolution = None
                if finding.urgency in osv.PROVISIONAL_URGENCIES:
                    # Hallazgos de antes de guardar la urgencia, o que Debian
                    # todavia no evaluo: puede haber cambiado desde ayer.
                    try:
                        vuln = await osv.get_vuln(vuln_id)
                        finding.urgency = osv.extract_urgency(vuln, package.name, ecosystem)
                        finding.severity = osv.extract_severity(vuln, finding.urgency)
                    except Exception:
                        logger.warning("No se pudo actualizar la urgencia de %s", vuln_id)
                pkg_findings.append(finding)
                continue

            try:
                vuln = await osv.get_vuln(vuln_id)
            except Exception:
                logger.exception("Fallo al pedir detalle de %s", vuln_id)
                continue

            urgency = osv.extract_urgency(vuln, package.name, ecosystem)
            finding = VulnerabilityFinding(
                host_id=host.id,
                package_name=package.name,
                package_version=package.version,
                vuln_id=vuln_id,
                summary=vuln.get("summary") or vuln.get("details", "")[:300],
                severity=osv.extract_severity(vuln, urgency),
                urgency=urgency,
                fixed_version=osv.extract_fixed_version(vuln, package.name, ecosystem),
                source_url=osv.extract_source_url(vuln),
                not_applicable=not_applicable_reason(package),
            )
            session.add(finding)
            pkg_findings.append(finding)
            added = True
            new_findings += 1

        await session.commit()

        # Regenerar si cambio el conjunto de CVEs (nuevos o arreglados) o si
        # lo guardado no sirve (ver _needs_new_recommendation).
        dropped = any(
            name == package.name and vid not in vuln_ids and f.status != "resolved"
            for (name, vid), f in existing.items()
        )
        if pkg_findings and (added or dropped or _needs_new_recommendation(host, package, pkg_findings)):
            rec = await _generate_recommendation(host, package, pkg_findings)
            if rec:
                source = "fija" if rec.endswith(FIXED_NOTE) or rec.endswith(FALLBACK_NOTE) else "ia_local"
                for f in pkg_findings:
                    f.ai_recommendation, f.rec_source = rec, source
                    f.audited_at, f.audit_note = None, None
                await session.commit()

    # Lo que OSV ya no reporta para la version instalada ahora (paquete
    # actualizado o desinstalado) queda resuelto. Seguro de hacer aca: la
    # consulta a OSV de arriba fue completa o el escaneo ya habria salido.
    installed = {src.name: src for src in sources}
    resolved = 0
    for key, finding in existing.items():
        if key not in still_present and finding.status != "resolved":
            finding.status = "resolved"
            finding.resolved_at = now
            src = installed.get(finding.package_name)
            finding.resolution = (
                f"actualizado a {src.version} (antes {finding.package_version})"
                if src and src.version != finding.package_version
                else ("ya no figura en OSV para la version instalada" if src else "paquete desinstalado")
            )
            resolved += 1
    host.last_vuln_scan_at = now
    await session.commit()
    _last_result[str(host.id)] = {"new": new_findings, "resolved": resolved, "finished_at": now.isoformat()}
    return new_findings


# Estado en memoria del escaneo por host (un solo proceso de servidor):
# "waiting_inventory" (se pidio al agente el inventario actual) o "scanning".
_state: dict[str, str] = {}
_waiting_since: dict[str, datetime] = {}
_last_result: dict[str, dict] = {}
_locks: dict[str, asyncio.Lock] = {}
# Un agente responde a send_inventory en ~10 s (sondeo de comandos). Si no
# llego nada en este tiempo (agente apagado, o version vieja que no conoce
# el comando), se deja de esperar en vez de quedar "esperando" para siempre.
WAITING_TIMEOUT_SECONDS = 120


def _lock(host_id: str) -> asyncio.Lock:
    return _locks.setdefault(host_id, asyncio.Lock())


def mark_waiting_inventory(host_id: str) -> None:
    _state[host_id] = "waiting_inventory"
    _waiting_since[host_id] = datetime.now(timezone.utc)


def inventory_request_failed(host_id: str, reason: str) -> None:
    if _state.get(host_id) == "waiting_inventory":
        _state.pop(host_id, None)
        _last_result[host_id] = {"error": reason, "finished_at": datetime.now(timezone.utc).isoformat()}


def scan_status(host_id: str) -> dict:
    since = _waiting_since.get(host_id)
    if (
        _state.get(host_id) == "waiting_inventory"
        and since
        and (datetime.now(timezone.utc) - since).total_seconds() > WAITING_TIMEOUT_SECONDS
    ):
        inventory_request_failed(
            host_id, "el agente no mando el inventario en 2 minutos (apagado o version sin soporte para este boton)"
        )
    return {"state": _state.get(host_id, "idle"), "last_result": _last_result.get(host_id)}


async def _locked_scan(session: AsyncSession, host: Host) -> int:
    """Un solo escaneo a la vez por host: el diario y el de "Escanear ahora"
    o el que dispara un inventario nuevo pueden coincidir."""
    host_id = str(host.id)
    async with _lock(host_id):
        _state[host_id] = "scanning"
        try:
            return await scan_host(session, host)
        finally:
            _state.pop(host_id, None)


async def scan_host_by_id(host_id) -> None:
    """Escaneo de un host apenas llega su inventario (envio diario del
    agente, reinstalacion o "Escanear ahora")."""
    try:
        async with SessionLocal() as session:
            host = (await session.execute(select(Host).where(Host.id == host_id))).scalar_one_or_none()
            if host is None:
                return
            found = await _locked_scan(session, host)
            if found:
                logger.info("Host %s: %d vulnerabilidades nuevas", host.name, found)
    except Exception:
        _state.pop(str(host_id), None)
        logger.exception("Fallo el escaneo de vulnerabilidades del host %s", host_id)


async def scan_all_hosts() -> None:
    async with SessionLocal() as session:
        hosts = (await session.execute(select(Host))).scalars().all()
        for host in hosts:
            try:
                found = await _locked_scan(session, host)
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
