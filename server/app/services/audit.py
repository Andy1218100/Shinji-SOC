"""Auditoria de la IA local por un modelo externo (Claude via el servidor MCP
de tools/mcp_audit, con la suscripcion del admin, sin API key).

El informe lo arma codigo, no la IA local: tiene que ser exacto (es lo que
el auditor compara) y gastar pocos tokens. Solo lleva lo necesario para
juzgar las recomendaciones: datos publicos de OSV (paquete, version, CVE,
resumen) y el texto que escribio la IA local. Nada que identifique a una
persona ni a la infraestructura: los hosts van como H1, H2...; sin nombres
de host, IPs, usuarios, rutas de /home, logs ni lineas de comando. Criterio
de minimizacion pensado para la Ley 21.719 de Chile (no es una opinion
legal: revisarlo con quien corresponda).
"""

import re
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AIRule
from app.models.host import Host
from app.models.vulnerability import InstalledPackage, VulnerabilityFinding
from app.services import ai, osv

# ~20 paquetes por lote: unos 4-5 mil tokens (medido con 30: ~8.700).
REPORT_DEFAULT_LIMIT = 20
EXAMPLES_PER_ITEM = 2
SUMMARY_CHARS = 110
MAX_RULE_CHARS = 300
MAX_RULES_PER_CALL = 10
MAX_ACTIVE_RULES = 50
MAX_RECOMMENDATION_CHARS = 1200
SCOPE = "vuln_recommendation"

# Solo rangos privados: un patron IPv4 generico tambien borra versiones
# como "7.1.1.43" (imagemagick). Las IPs registradas de los hosts se
# reemplazan aparte, una por una.
_IPV4 = re.compile(r"\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01])|169\.254)\.\d{1,3}\.\d{1,3}\b")
_IPV6 = re.compile(r"\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b", re.IGNORECASE)
_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
_HOME = re.compile(r"/home/[^/\s]+")


def _alias_map(hosts: list[Host]) -> dict:
    ordered = sorted(hosts, key=lambda h: (h.created_at or datetime.min.replace(tzinfo=timezone.utc), str(h.id)))
    return {h.id: f"H{i}" for i, h in enumerate(ordered, start=1)}


def scrub(text: str | None, hosts: list[Host], aliases: dict) -> str:
    """Saca de un texto libre (resumen de OSV, texto de la IA local) lo que
    pueda identificar a la infraestructura o a una persona."""
    if not text:
        return ""
    out = text
    for h in hosts:
        for ident in {h.name, h.hostname, h.ip_address}:
            if ident and len(ident) >= 3:
                out = re.sub(re.escape(ident), aliases[h.id], out, flags=re.IGNORECASE)
    out = _EMAIL.sub("[email]", out)
    out = _IPV4.sub("[ip]", out)
    out = _IPV6.sub("[ip]", out)
    out = _HOME.sub("/home/[usuario]", out)
    return out


def _is_ai_text(text: str | None) -> bool:
    from app.services.vuln_scan import FALLBACK_NOTE, FIXED_NOTE

    return bool(text) and not text.endswith(FIXED_NOTE) and not text.endswith(FALLBACK_NOTE)


async def active_rules(session: AsyncSession, scope: str = SCOPE) -> list[AIRule]:
    return list(
        (
            await session.execute(
                select(AIRule).where(AIRule.scope == scope, AIRule.active.is_(True)).order_by(AIRule.created_at.desc())
            )
        ).scalars().all()
    )


async def build_report(session: AsyncSession, limit: int = REPORT_DEFAULT_LIMIT) -> dict:
    hosts = list((await session.execute(select(Host))).scalars().all())
    aliases = _alias_map(hosts)
    findings = (
        await session.execute(
            select(VulnerabilityFinding).where(
                VulnerabilityFinding.status != "resolved",
                VulnerabilityFinding.audited_at.is_(None),
                VulnerabilityFinding.ai_recommendation.is_not(None),
            )
        )
    ).scalars().all()

    groups: dict[tuple, list[VulnerabilityFinding]] = {}
    for f in findings:
        if f.rec_source == "claude" or not _is_ai_text(f.ai_recommendation):
            continue
        groups.setdefault((f.host_id, f.package_name), []).append(f)

    binaries: dict[tuple, list[str]] = {}
    for host_id, name, source in (
        await session.execute(select(InstalledPackage.host_id, InstalledPackage.name, InstalledPackage.source_name))
    ).all():
        binaries.setdefault((host_id, source or name), []).append(name)

    def priority(item):
        fs = item[1]
        relevant = sum(1 for f in fs if f.urgency != osv.UNIMPORTANT)
        return (-sum(1 for f in fs if f.fixed_version), -relevant, -len(fs))

    items = []
    for (host_id, package), fs in sorted(groups.items(), key=priority)[:limit]:
        relevant = [f for f in fs if f.urgency != osv.UNIMPORTANT] or fs
        examples = sorted(relevant, key=lambda f: (f.severity != "critical", f.vuln_id))[:EXAMPLES_PER_ITEM]
        urgencies: dict[str, int] = {}
        for f in fs:
            urgencies[f.urgency or "sin dato"] = urgencies.get(f.urgency or "sin dato", 0) + 1
        alias = aliases.get(host_id, "H?")
        items.append(
            {
                "id": f"{alias}|{package}",
                "host": alias,
                "paquete_fuente": package,
                "version": fs[0].package_version,
                "binarios": sorted(binaries.get((host_id, package), []))[:4],
                "cves": len(fs),
                "urgencia_debian": urgencies,
                "versiones_corregidas": sorted({f.fixed_version for f in fs if f.fixed_version})[:3],
                "ejemplos": [
                    {"cve": f.vuln_id, "resumen": scrub((f.summary or "")[:SUMMARY_CHARS], hosts, aliases)}
                    for f in examples
                ],
                "recomendacion_ia_local": scrub(fs[0].ai_recommendation, hosts, aliases),
            }
        )

    rules = await active_rules(session)
    return {
        "generado": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "pendientes_total": len(groups),
        "incluidos": len(items),
        "hosts": {aliases[h.id]: {"debian": h.debian_release} for h in hosts},
        "reglas_activas": [{"paquete": r.package_name, "regla": r.rule} for r in rules],
        "items": items,
    }


async def apply_feedback(session: AsyncSession, items: list[dict], rules: list[dict]) -> dict:
    hosts = list((await session.execute(select(Host))).scalars().all())
    by_alias = {alias: host_id for host_id, alias in _alias_map(hosts).items()}
    now = datetime.now(timezone.utc)
    applied, rejected = [], []

    for item in items:
        item_id = str(item.get("id", ""))
        alias, _, package = item_id.partition("|")
        host_id = by_alias.get(alias)
        if not host_id or not package:
            rejected.append({"id": item_id, "motivo": "id desconocido"})
            continue
        fs = (
            await session.execute(
                select(VulnerabilityFinding).where(
                    VulnerabilityFinding.host_id == host_id,
                    VulnerabilityFinding.package_name == package,
                    VulnerabilityFinding.status != "resolved",
                )
            )
        ).scalars().all()
        if not fs:
            rejected.append({"id": item_id, "motivo": "el paquete ya no tiene hallazgos abiertos"})
            continue

        verdict = item.get("verdict")
        note = (item.get("note") or "")[:500] or None
        if verdict == "ok":
            for f in fs:
                f.audited_at, f.audit_note = now, note
            applied.append(item_id)
        elif verdict == "fix":
            text = (item.get("corrected_recommendation") or "").strip()
            if not text or len(text) > MAX_RECOMMENDATION_CHARS:
                rejected.append({"id": item_id, "motivo": f"falta el texto corregido o pasa de {MAX_RECOMMENDATION_CHARS} caracteres"})
                continue
            source = " ".join(
                [package, fs[0].package_version, *(f.vuln_id for f in fs), *(f.fixed_version or "" for f in fs), *(f.summary or "" for f in fs)]
            )
            if invented := ai.ungrounded_identifiers(text, source):
                rejected.append({"id": item_id, "motivo": f"cita datos que no estan en los hallazgos: {', '.join(invented)}"})
                continue
            for f in fs:
                f.ai_recommendation, f.rec_source, f.audited_at, f.audit_note = text, "claude", now, note
            applied.append(item_id)
        else:
            rejected.append({"id": item_id, "motivo": "verdict debe ser 'ok' o 'fix'"})

    existing = await active_rules(session)
    known = {(r.package_name, r.rule.strip().lower()) for r in existing}
    added_rules = 0
    for rule in rules[:MAX_RULES_PER_CALL]:
        text = (rule.get("rule") or "").strip()
        package = (rule.get("package") or None) or None
        if not text or len(text) > MAX_RULE_CHARS:
            rejected.append({"regla": text[:60], "motivo": f"vacia o mas de {MAX_RULE_CHARS} caracteres"})
            continue
        if (package, text.lower()) in known:
            continue
        if len(existing) + added_rules >= MAX_ACTIVE_RULES:
            rejected.append({"regla": text[:60], "motivo": f"ya hay {MAX_ACTIVE_RULES} reglas activas"})
            continue
        session.add(AIRule(scope=SCOPE, package_name=package, rule=text, source="claude"))
        known.add((package, text.lower()))
        added_rules += 1

    await session.commit()
    return {"aplicados": applied, "reglas_nuevas": added_rules, "rechazados": rejected}
