"""Lo que detecta el WAF opcional (waf.sh: nginx + ModSecurity + OWASP CRS).

ModSecurity escribe una linea JSON por peticion sospechosa en
/var/log/shinji-soc-waf/audit.log. Aca se queda solo con las que superan el
umbral de CRS (las que el WAF bloquea, o bloquearia en modo deteccion) y se
manda un resumen: hora, IP, metodo, ruta, codigo de respuesta y las reglas
que coincidieron. Nunca las cabeceras (llevan cookies de sesion) ni los
cuerpos.
"""

import json
import os
from datetime import datetime

import log_tailer

AUDIT_LOG = os.environ.get("SHINJI_SOC_WAF_LOG", "/var/log/shinji-soc-waf/audit.log")
MODE_FILE = "/etc/shinji-soc-waf/modo.conf"
STATE_PATH = os.environ.get(
    "SHINJI_SOC_WAF_STATE", os.path.join(os.path.dirname(os.path.abspath(__file__)), "waf_state.json")
)
MAX_ENTRIES_PER_READ = 1000

# Reglas de CRS que suman el puntaje y deciden el bloqueo: entrante
# (949110) y saliente (959100). Las 2000xx son de la configuracion base
# (cuerpo de la peticion que no se puede analizar) y bloquean por si solas.
THRESHOLD_RULES = {"949110", "959100"}
SUMMARY_RULES = THRESHOLD_RULES | {"980130", "980140", "980170"}
MAX_RULES = 8
SEVERITY_NAMES = {"0": "emergencia", "1": "alerta", "2": "critica", "3": "error", "4": "advertencia", "5": "aviso"}


def available() -> bool:
    return os.path.exists(AUDIT_LOG)


def mode() -> str | None:
    """'bloqueo' o 'deteccion', segun /etc/shinji-soc-waf/modo.conf."""
    try:
        with open(MODE_FILE, encoding="utf-8") as fh:
            text = fh.read()
    except OSError:
        return None
    return "bloqueo" if "SecRuleEngine On" in text else "deteccion"


def sites() -> list[str]:
    """Los sitios que protege, como 'amp: 127.0.0.1:8081 -> http://127.0.0.1:8080'."""
    folder = "/etc/shinji-soc-waf/sitios"
    result = []
    try:
        names = sorted(n for n in os.listdir(folder) if n.endswith(".conf"))
    except OSError:
        return []
    for name in names:
        try:
            with open(os.path.join(folder, name), encoding="utf-8") as fh:
                first = fh.readline()
        except OSError:
            continue
        marker = "del WAF de Shinji SOC: "
        target = first.split(marker, 1)[1].strip() if marker in first else ""
        result.append(f"{name[:-5]}: {target}"[:200])
    return result


def _parse_time(text: str) -> str | None:
    """'Thu Nov 26 13:17:07 2026' esta en la hora local del host, sin zona:
    se le agrega la zona del sistema, que es la del propio host."""
    try:
        return datetime.strptime(text, "%a %b %d %H:%M:%S %Y").astimezone().isoformat()
    except (TypeError, ValueError):
        return None


def parse_line(line: str) -> dict | None:
    try:
        tx = json.loads(line)["transaction"]
    except (ValueError, KeyError, TypeError):
        return None
    if not isinstance(tx, dict):
        return None
    messages = [m for m in tx.get("messages") or [] if isinstance(m, dict)]
    rule_ids = {str((m.get("details") or {}).get("ruleId", "")) for m in messages}
    response = tx.get("response") or {}
    if not (rule_ids & THRESHOLD_RULES or any(r.startswith("2000") for r in rule_ids)):
        return None  # solo avisos sueltos, por debajo del umbral
    # En modo deteccion el motor figura como "DetectionOnly" y no bloquea.
    blocked = (tx.get("producer") or {}).get("secrules_engine") == "Enabled"

    score = None
    rules = []
    for m in messages:
        details = m.get("details") or {}
        rid = str(details.get("ruleId", ""))
        text = str(m.get("message") or "")
        if rid in ("949110", "959100") and "Total Score:" in text:
            try:
                score = int(text.split("Total Score:", 1)[1].strip(" )").split(")")[0])
            except ValueError:
                pass
        if rid in SUMMARY_RULES or len(rules) >= MAX_RULES:
            continue
        if any(r["id"] == rid for r in rules):
            continue
        tags = [t for t in details.get("tags") or [] if isinstance(t, str) and t.startswith("attack-")]
        rules.append({
            "id": rid[:12],
            "msg": text[:160],
            "severity": SEVERITY_NAMES.get(str(details.get("severity", "")), str(details.get("severity", ""))[:12]),
            "attack": tags[0][7:][:32] if tags else None,
            "data": str(details.get("data") or "")[:200],
        })

    request = tx.get("request") or {}
    host = (request.get("headers") or {}).get("Host") or (request.get("headers") or {}).get("host")
    return {
        "ts": _parse_time(tx.get("time_stamp")),
        "ip": str(tx.get("client_ip") or "")[:64],
        "method": str(request.get("method") or "")[:16],
        "uri": str(request.get("uri") or "")[:500],
        "host": str(host)[:200] if host else None,
        "status_code": response.get("http_code") if isinstance(response.get("http_code"), int) else None,
        "blocked": bool(blocked),
        "score": score,
        "rules": rules,
    }


def read_new_entries(max_entries: int = MAX_ENTRIES_PER_READ) -> list[dict]:
    return log_tailer.tail([AUDIT_LOG], STATE_PATH, parse_line, max_entries)
