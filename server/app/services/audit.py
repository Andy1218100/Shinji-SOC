"""Auditoria de la IA local por un modelo externo (Claude via el servidor MCP
de tools/mcp_audit, con la suscripcion del admin, sin API key).

Tres ambitos: recomendaciones de vulnerabilidades, resumenes de eventos de
seguridad e informes de los hosts. El informe lo arma codigo, no la IA
local: tiene que ser exacto (es lo que el auditor compara) y gastar pocos
tokens.

Minimizacion de datos (pensada para la Ley 21.719 de Chile; no es una
opinion legal, revisarlo con quien corresponda):
- hosts como H1, H2...: sin nombres de host ni sus IPs;
- IPs de origen como seudonimos estables (IP-3fa9c1, HMAC con una clave
  del servidor): el auditor ve que dos eventos vienen de la misma IP sin
  conocerla;
- sin nombres de usuario probados por SSH (solo cuantos y si fue root),
  sin user-agent, y lineas de comando y rutas sin IPs, correos ni /home.
Al guardar una correccion, los alias y seudonimos se vuelven a reemplazar
por el nombre del host y la IP reales, para que el texto se lea bien en
el panel.
"""

import hashlib
import hmac
import re
import uuid as uuidlib
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.audit import AIRule
from app.models.host import Host
from app.models.security import SecurityEvent
from app.models.system_report import SystemReport
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
CMDLINE_CHARS = 200

SCOPE = "vuln_recommendation"
SCOPES = {"vulnerabilidades": "vuln_recommendation", "eventos": "security_event", "informes": "host_report"}

# Solo rangos privados: un patron IPv4 generico tambien borra versiones
# como "7.1.1.43" (imagemagick). Las IPs registradas de los hosts se
# reemplazan aparte, una por una.
_IPV4 = re.compile(r"\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01])|169\.254)\.\d{1,3}\.\d{1,3}\b")
_IPV6 = re.compile(r"\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b", re.IGNORECASE)
_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
_HOME = re.compile(r"/home/[^/\s]+")
# En eventos (lineas de comando, rutas) toda IPv4 valida es una IP: ahi no
# hay numeros de version de paquetes que confundir.
_ANY_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")


def _alias_map(hosts: list[Host]) -> dict:
    ordered = sorted(hosts, key=lambda h: (h.created_at or datetime.min.replace(tzinfo=timezone.utc), str(h.id)))
    return {h.id: f"H{i}" for i, h in enumerate(ordered, start=1)}


def _replace_ident(text: str, ident: str, alias: str) -> str:
    """Reemplaza el nombre/IP del host solo como palabra completa: un host
    llamado "AMP" no debe convertir ".ampdata" o "AMP_Logs" (rutas de la
    aplicacion AMP) en ".H1data" o "H1_Logs"."""
    return re.sub(rf"(?<![\w.-]){re.escape(ident)}(?![\w-])", alias, text, flags=re.IGNORECASE)


def pseudo_ip(ip: str | None) -> str:
    """Seudonimo estable de una IP: el mismo en cada informe, sin revelarla."""
    if not ip:
        return ""
    digest = hmac.new(settings.session_secret_key.encode(), ip.encode(), hashlib.sha256).hexdigest()
    return f"IP-{digest[:6]}"


def scrub(text: str | None, hosts: list[Host], aliases: dict) -> str:
    """Saca de un texto libre (resumen de OSV, texto de la IA local) lo que
    pueda identificar a la infraestructura o a una persona."""
    if not text:
        return ""
    out = text
    for h in hosts:
        for ident in {h.name, h.hostname, h.ip_address}:
            if ident and len(ident) >= 3:
                out = _replace_ident(out, ident, aliases[h.id])
    out = _EMAIL.sub("[email]", out)
    out = _IPV4.sub("[ip]", out)
    out = _IPV6.sub("[ip]", out)
    out = _HOME.sub("/home/[usuario]", out)
    return out


def scrub_event_text(text: str | None, hosts: list[Host], aliases: dict) -> str:
    """Como scrub, pero toda IP pasa a seudonimo (en eventos importa saber
    si dos IPs son la misma)."""
    out = text or ""
    for h in hosts:
        for ident in {h.name, h.hostname}:
            if ident and len(ident) >= 3:
                out = _replace_ident(out, ident, aliases[h.id])
    out = re.sub(r"::ffff:", "", out, flags=re.IGNORECASE)
    out = _ANY_IPV4.sub(lambda m: pseudo_ip(m.group(0)), out)
    out = _IPV6.sub(lambda m: pseudo_ip(m.group(0)), out)
    out = _EMAIL.sub("[email]", out)
    return _HOME.sub("/home/[usuario]", out)


def restore(text: str, host: Host | None, alias: str, ips: list[str]) -> str:
    """Inverso de scrub para guardar una correccion: alias y seudonimos
    vuelven a ser el nombre del host y las IPs reales."""
    out = text
    for ip in ips:
        if ip:
            out = out.replace(pseudo_ip(ip), ip)
    if host is not None and alias:
        out = re.sub(rf"\b{re.escape(alias)}\b", host.name, out)
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


def rules_text(rules: list[AIRule], subject: str | None, max_general: int = 5, max_specific: int = 3) -> str:
    """Reglas del auditor para agregar al prompt de la IA local: las del tema
    puntual (paquete o tipo de evento) primero, despues las generales."""
    general = [r.rule for r in rules if r.package_name is None][:max_general]
    specific = [r.rule for r in rules if subject and r.package_name == subject][:max_specific]
    chosen = specific + general
    if not chosen:
        return ""
    return " Reglas de un auditor que reviso respuestas anteriores (respetalas): " + " ".join(
        f"({i}) {r}" for i, r in enumerate(chosen, start=1)
    )


# ---------------------------------------------------------------- informes

async def build_report(session: AsyncSession, limit: int = REPORT_DEFAULT_LIMIT, tipo: str = "vulnerabilidades") -> dict:
    if tipo not in SCOPES:
        raise ValueError("tipo debe ser vulnerabilidades, eventos o informes")
    hosts = list((await session.execute(select(Host))).scalars().all())
    aliases = _alias_map(hosts)
    builder = {"vulnerabilidades": _vuln_items, "eventos": _event_items, "informes": _host_report_items}[tipo]
    pending, items = await builder(session, hosts, aliases, limit)
    rules = await active_rules(session, SCOPES[tipo])
    return {
        "tipo": tipo,
        "generado": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "pendientes_total": pending,
        "incluidos": len(items),
        "hosts": {aliases[h.id]: {"debian": h.debian_release} for h in hosts},
        "reglas_activas": [{"sobre": r.package_name, "regla": r.rule} for r in rules],
        "items": items,
    }


async def _vuln_items(session, hosts, aliases, limit):
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
        items.append({
            "id": f"{alias}|{package}",
            "host": alias,
            "paquete_fuente": package,
            "version": fs[0].package_version,
            "binarios": sorted(binaries.get((host_id, package), []))[:4],
            "cves": len(fs),
            "urgencia_debian": urgencies,
            "versiones_corregidas": sorted({f.fixed_version for f in fs if f.fixed_version})[:3],
            "ejemplos": [{"cve": f.vuln_id, "resumen": scrub((f.summary or "")[:SUMMARY_CHARS], hosts, aliases)} for f in examples],
            "recomendacion_ia_local": scrub(fs[0].ai_recommendation, hosts, aliases),
        })
    return len(groups), items


def _event_facts(e: SecurityEvent, hosts, aliases) -> dict:
    """Lo que el auditor necesita para juzgar el resumen, ya minimizado."""
    from app.services import ids

    d = e.detail or {}
    source = e.source_ip or ""
    local = source.startswith("local:")
    facts: dict = {"origen": "local (proceso en el host)" if local else pseudo_ip(source)}
    if e.kind == "process_anomaly":
        cmd, parent = str(d.get("cmdline") or ""), str(d.get("parent_cmdline") or "")
        bad, good = ids.process_signal_lists(cmd, parent)
        facts.update({
            "cuenta": d.get("user"),
            "comando": scrub_event_text(cmd[:CMDLINE_CHARS], hosts, aliases),
            "proceso_padre": scrub_event_text(parent[:CMDLINE_CHARS], hosts, aliases),
            "senales_intrusion": bad, "senales_legitimo": good,
        })
    elif e.kind in ("ssh_brute_force", "pve_brute_force"):
        facts.update({"servicio": d.get("service"), "fallos": d.get("failures"), "ventana_s": d.get("window_seconds"),
                      "usuarios_distintos": d.get("distinct_users"), "probo_root": d.get("root_targeted")})
    elif e.kind == "login_after_failures":
        facts.update({"servicio": d.get("service"), "metodo": d.get("method"), "fallos_previos": d.get("failures"),
                      "ventana_s": d.get("window_seconds"),
                      "usuario_es_root": str(d.get("user") or "").split("@")[0] == "root"})
    elif e.kind == "new_listener":
        facts.update({"protocolo": d.get("proto"), "puerto": d.get("port"),
                      "solo_local": str(d.get("address") or "") in ("127.0.0.1", "::1"),
                      "proceso": scrub_event_text(str(d.get("cmdline") or d.get("process") or "")[:CMDLINE_CHARS], hosts, aliases)})
    elif e.kind in ("service_outbound", "malicious_connection"):
        facts.update({"puerto_remoto": d.get("remote_port"), "cuenta": d.get("user"),
                      "proceso": scrub_event_text(str(d.get("cmdline") or d.get("process") or "")[:CMDLINE_CHARS], hosts, aliases)})
    elif e.kind == "waf_attack":
        facts.update({"peticiones": d.get("hits"), "bloqueadas": d.get("blocked"), "modo_waf": d.get("mode"),
                      "tipos_de_ataque": d.get("attack_types"),
                      "reglas": [scrub_event_text(str(r)[:120], hosts, aliases) for r in (d.get("top_rules") or [])[:6]],
                      "ruta_ejemplo": scrub_event_text(str(d.get("sample_uri") or "")[:CMDLINE_CHARS], hosts, aliases)})
    elif "path" in d:
        facts.update({"ruta": scrub_event_text(str(d.get("path"))[:CMDLINE_CHARS], hosts, aliases), "metodo": d.get("method")})
    else:
        facts.update({k: v for k, v in d.items() if k in ("requests_in_window", "not_found_in_window", "window_seconds")})
    if d.get("lista_de_amenazas"):
        facts["en_lista_de_amenazas"] = True
    if d.get("detras_de_proxy") or d.get("ip_de_proxy"):
        facts["ip_de_proxy"] = True
    return facts


async def _event_items(session, hosts, aliases, limit):
    events = (
        await session.execute(
            select(SecurityEvent)
            .where(SecurityEvent.ai_summary.is_not(None), SecurityEvent.audited_at.is_(None))
            .order_by(SecurityEvent.created_at.desc())
        )
    ).scalars().all()
    pending = [e for e in events if e.ai_source != "claude"]
    items = []
    for e in pending[:limit]:
        items.append({
            "id": f"E|{e.id}",
            "host": aliases.get(e.host_id, "H?"),
            "tipo": e.kind,
            "severidad": e.severity,
            "accion_sugerida": e.suggested_action,
            "hechos": _event_facts(e, hosts, aliases),
            "resumen_ia_local": scrub_event_text(e.ai_summary, hosts, aliases),
        })
    return len(pending), items


def _report_facts(raw: dict, hosts, aliases) -> dict:
    ports = [f"{p.get('port')}" + (f" ({p.get('process')})" if p.get("process") else "") for p in raw.get("listening_ports") or []]
    return {
        "sistema": raw.get("os_name"),
        "cpus": raw.get("cpu_count"),
        "ram_mb": round(raw["mem_total_mb"]) if raw.get("mem_total_mb") else None,
        "disco_gb": round(raw["disk_total_gb"]) if raw.get("disk_total_gb") else None,
        "servicios": (raw.get("services") or [])[:20],
        "puertos": ports[:25],
        "logs_vigilados": len(raw.get("log_paths") or []),
        "otros_logs_no_leidos": raw.get("other_log_paths_total") or len(raw.get("other_log_paths") or []),
        "waf": {"modo": raw.get("waf_mode"), "sitios": len(raw.get("waf_sites") or [])} if raw.get("waf_mode") else None,
        "logs_sin_permiso": [scrub(p, hosts, aliases) for p in (raw.get("unreadable_log_paths") or [])[:10]],
        "carpetas_sin_acceso": [scrub(p, hosts, aliases) for p in (raw.get("denied_log_dirs") or [])[:10]],
        "cuentas_de_servicio": (raw.get("service_accounts") or [])[:15],
        "logins_ssh_vigilados": bool(raw.get("auth_log_source")),
    }


async def _host_report_items(session, hosts, aliases, limit):
    reports = (
        await session.execute(
            select(SystemReport).where(SystemReport.ai_summary.is_not(None), SystemReport.audited_at.is_(None))
        )
    ).scalars().all()
    pending = [r for r in reports if r.ai_source != "claude"]
    items = []
    for r in pending[:limit]:
        alias = aliases.get(r.host_id, "H?")
        items.append({
            "id": f"R|{alias}",
            "host": alias,
            "hechos": _report_facts(r.raw or {}, hosts, aliases),
            "informe_ia_local": scrub(r.ai_summary, hosts, aliases),
        })
    return len(pending), items


# ---------------------------------------------------------- correcciones

async def apply_feedback(session: AsyncSession, items: list[dict], rules: list[dict]) -> dict:
    hosts = list((await session.execute(select(Host))).scalars().all())
    aliases = _alias_map(hosts)
    by_alias = {alias: host_id for host_id, alias in aliases.items()}
    by_id = {h.id: h for h in hosts}
    now = datetime.now(timezone.utc)
    applied, rejected = [], []

    for item in items:
        item_id = str(item.get("id", ""))
        verdict = item.get("verdict")
        note = (item.get("note") or "")[:500] or None
        text = (item.get("corrected_recommendation") or "").strip()
        if verdict not in ("ok", "fix"):
            rejected.append({"id": item_id, "motivo": "verdict debe ser 'ok' o 'fix'"})
            continue
        if verdict == "fix" and (not text or len(text) > MAX_RECOMMENDATION_CHARS):
            rejected.append({"id": item_id, "motivo": f"falta el texto corregido o pasa de {MAX_RECOMMENDATION_CHARS} caracteres"})
            continue

        if item_id.startswith("E|"):
            result = await _apply_event(session, item_id, verdict, text, note, now, by_id, aliases)
        elif item_id.startswith("R|"):
            result = await _apply_report(session, item_id, verdict, text, note, now, by_alias, by_id)
        else:
            result = await _apply_vuln(session, item_id, verdict, text, note, now, by_alias, by_id)
        if result:
            rejected.append({"id": item_id, "motivo": result})
        else:
            applied.append(item_id)

    added_rules = await _add_rules(session, rules, rejected)
    await session.commit()
    return {"aplicados": applied, "reglas_nuevas": added_rules, "rechazados": rejected}


async def _apply_vuln(session, item_id, verdict, text, note, now, by_alias, by_id) -> str | None:
    alias, _, package = item_id.partition("|")
    host_id = by_alias.get(alias)
    if not host_id or not package:
        return "id desconocido"
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
        return "el paquete ya no tiene hallazgos abiertos"
    if verdict == "fix":
        source = " ".join([package, fs[0].package_version, *(f.vuln_id for f in fs),
                           *(f.fixed_version or "" for f in fs), *(f.summary or "" for f in fs)])
        if invented := ai.ungrounded_identifiers(text, source):
            return f"cita datos que no estan en los hallazgos: {', '.join(invented)}"
        text = restore(text, by_id.get(host_id), alias, [])
    for f in fs:
        if verdict == "fix":
            f.ai_recommendation, f.rec_source = text, "claude"
        f.audited_at, f.audit_note = now, note
    return None


async def _apply_event(session, item_id, verdict, text, note, now, by_id, aliases) -> str | None:
    try:
        event_id = uuidlib.UUID(item_id[2:])
    except ValueError:
        return "id desconocido"
    event = await session.get(SecurityEvent, event_id)
    if event is None:
        return "el evento ya no existe"
    if verdict == "fix":
        host = by_id.get(event.host_id)
        ips = [event.source_ip] + _ANY_IPV4.findall(str(event.detail or ""))
        event.ai_summary = restore(text, host, aliases.get(event.host_id, ""), ips)
        event.ai_source = "claude"
    event.audited_at, event.audit_note = now, note
    return None


async def _apply_report(session, item_id, verdict, text, note, now, by_alias, by_id) -> str | None:
    alias = item_id[2:]
    host_id = by_alias.get(alias)
    report = (
        await session.execute(select(SystemReport).where(SystemReport.host_id == host_id))
    ).scalar_one_or_none() if host_id else None
    if report is None:
        return "id desconocido"
    if verdict == "fix":
        report.ai_summary = restore(text, by_id.get(host_id), alias, [])
        report.ai_source = "claude"
    report.audited_at, report.audit_note = now, note
    return None


async def _add_rules(session, rules: list[dict], rejected: list) -> int:
    added = 0
    for rule in rules[:MAX_RULES_PER_CALL]:
        text = (rule.get("rule") or "").strip()
        subject = (rule.get("package") or rule.get("sobre") or None) or None
        scope = SCOPES.get(rule.get("ambito") or "vulnerabilidades")
        if scope is None:
            rejected.append({"regla": text[:60], "motivo": "ambito debe ser vulnerabilidades, eventos o informes"})
            continue
        if not text or len(text) > MAX_RULE_CHARS:
            rejected.append({"regla": text[:60], "motivo": f"vacia o mas de {MAX_RULE_CHARS} caracteres"})
            continue
        existing = await active_rules(session, scope)
        if any(r.package_name == subject and r.rule.strip().lower() == text.lower() for r in existing):
            continue
        if len(existing) >= MAX_ACTIVE_RULES:
            rejected.append({"regla": text[:60], "motivo": f"ya hay {MAX_ACTIVE_RULES} reglas activas en {scope}"})
            continue
        session.add(AIRule(scope=scope, package_name=subject, rule=text, source="claude"))
        await session.flush()
        added += 1
    return added
