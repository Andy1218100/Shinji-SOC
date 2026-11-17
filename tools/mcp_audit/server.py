"""Servidor MCP (stdio) para que Claude audite a la IA local de Shinji SOC.

Corre en la PC del admin, la que tiene Claude Code con su suscripcion; no
necesita API key de Anthropic. Solo usa la biblioteca estandar de Python
(el protocolo MCP por stdio es JSON-RPC 2.0, un mensaje por linea).

Configuracion (variables de entorno, o se leen del .env del proyecto):
  SHINJI_SOC_URL           URL del servidor (por defecto http://localhost:8000)
  SHINJI_SOC_AUDIT_TOKEN   el AUDIT_API_TOKEN del servidor

Registrar en Claude Code:
  claude mcp add --scope user shinji-soc-audit -- python "<ruta>/tools/mcp_audit/server.py"
"""

import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

SERVER_NAME = "shinji-soc-audit"
SERVER_VERSION = "1.0.0"
DEFAULT_PROTOCOL = "2025-06-18"


def _load_env_file() -> dict:
    env_path = Path(__file__).resolve().parents[2] / ".env"
    values = {}
    try:
        for line in env_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                values[key.strip()] = value.strip().strip('"').strip("'")
    except OSError:
        pass
    return values


_ENV = _load_env_file()
BASE_URL = os.environ.get("SHINJI_SOC_URL", "http://localhost:8000").rstrip("/")
TOKEN = os.environ.get("SHINJI_SOC_AUDIT_TOKEN") or _ENV.get("AUDIT_API_TOKEN", "")

AUDIT_GUIDE = """Tres tipos de informe (parametro "tipo" de obtener_informe). Para cada item: verdict "ok" si el texto de la IA local (un modelo de 3B) es correcto y util, o "fix" con "corrected_recommendation" (2-3 frases en espanol, solo con datos del item) si no.

vulnerabilidades (recomendacion por paquete):
- Si "versiones_corregidas" esta vacio NO hay parche en Debian: no puede decir que actualizar lo corrige ni citar versiones upstream de los resumenes ("before 0.23.0").
- No recomendar desinstalar paquetes base del sistema ni inventar versiones o CVEs.
- "unimportant" = sin impacto practico segun Debian; "not yet assigned" = Debian aun no lo evaluo.

eventos (resumen de un evento de seguridad):
- Debe ser coherente con "hechos" y "tipo": no inventar ataques, IPs, usuarios ni archivos.
- process_anomaly: juzgar con "senales_intrusion" / "senales_legitimo"; un proceso lanzado por systemd sin senales de intrusion no es un ataque. La accion es terminar el proceso, no bloquear una IP.
- Fuerza bruta: muchos usuarios distintos o root sugieren ataque automatizado. Decir claramente si conviene la "accion_sugerida".

informes (lectura del informe del host):
- Solo afirmar lo que esta en "hechos" (servicios, puertos, logs, cuentas): no inventar el tipo de servidor ni servicios. Senalar logs sin permiso o carpetas sin acceso si los hay.

Reglas: cuando un error se repita, agrega UNA regla corta (max 300 caracteres) en "reglas" con "ambito" (vulnerabilidades, eventos o informes) para que la IA local no lo repita; "sobre" opcional (un paquete o un tipo de evento). No repitas las de "reglas_activas".

Los datos ya vienen minimizados: hosts como H1, H2; IPs como seudonimos IP-xxxxxx (puedes usarlos en el texto corregido: se reemplazan por la IP real al guardar); sin usuarios ni rutas personales. No pidas mas datos."""

TOOLS = [
    {
        "name": "obtener_informe",
        "description": (
            "Devuelve un lote compacto de textos de la IA local de Shinji SOC que todavia no fueron "
            "auditados (recomendaciones de vulnerabilidades, resumenes de eventos de seguridad o informes "
            "de hosts), con los datos necesarios para juzgarlos y las reglas activas.\n\n" + AUDIT_GUIDE
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "tipo": {"type": "string", "enum": ["vulnerabilidades", "eventos", "informes"],
                         "default": "vulnerabilidades"},
                "limite": {"type": "integer", "minimum": 1, "maximum": 100, "default": 20,
                           "description": "Cuantos items traer (cada uno ~200-300 tokens)."},
            },
        },
    },
    {
        "name": "enviar_auditoria",
        "description": (
            "Guarda en Shinji SOC el resultado de la auditoria: veredicto por item (las correcciones "
            "reemplazan el texto de la IA local) y reglas nuevas que la IA local usara en sus proximas "
            "respuestas. El servidor rechaza correcciones que citen versiones o CVEs que no estan en los datos."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "items": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "string", "description": "El 'id' del item del informe (ej. 'H1|thrift', 'E|<uuid>', 'R|H1')."},
                            "verdict": {"type": "string", "enum": ["ok", "fix"]},
                            "corrected_recommendation": {"type": "string"},
                            "note": {"type": "string", "description": "Que estaba mal, en una frase."},
                        },
                        "required": ["id", "verdict"],
                    },
                },
                "reglas": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "rule": {"type": "string", "maxLength": 300},
                            "ambito": {"type": "string", "enum": ["vulnerabilidades", "eventos", "informes"]},
                            "sobre": {"type": "string", "description": "Opcional: paquete fuente o tipo de evento al que aplica."},
                        },
                        "required": ["rule"],
                    },
                },
            },
            "required": ["items"],
        },
    },
]


def _http(method: str, path: str, body: dict | None = None) -> dict:
    if not TOKEN:
        raise RuntimeError("Falta el token: define AUDIT_API_TOKEN en el .env del proyecto o SHINJI_SOC_AUDIT_TOKEN.")
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        BASE_URL + path, data=data, method=method,
        headers={"X-Audit-Token": TOKEN, "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:500]
        raise RuntimeError(f"Shinji SOC respondio {exc.code}: {detail}") from None
    except urllib.error.URLError as exc:
        raise RuntimeError(f"No se pudo conectar a {BASE_URL}: {exc.reason}") from None


def _call_tool(name: str, args: dict) -> str:
    if name == "obtener_informe":
        limit = int(args.get("limite") or 20)
        tipo = args.get("tipo") or "vulnerabilidades"
        if tipo not in ("vulnerabilidades", "eventos", "informes"):
            raise RuntimeError("tipo debe ser vulnerabilidades, eventos o informes")
        report = _http("GET", f"/api/v1/audit/report?limit={max(1, min(limit, 100))}&tipo={tipo}")
        return json.dumps(report, ensure_ascii=False, separators=(",", ":"))
    if name == "enviar_auditoria":
        body = {"items": args.get("items") or [], "rules": args.get("reglas") or []}
        return json.dumps(_http("POST", "/api/v1/audit/feedback", body), ensure_ascii=False)
    raise RuntimeError(f"Herramienta desconocida: {name}")


def _handle(msg: dict) -> dict | None:
    method, msg_id = msg.get("method"), msg.get("id")
    if msg_id is None:  # notificacion (p. ej. notifications/initialized): sin respuesta
        return None
    if method == "initialize":
        result = {
            "protocolVersion": (msg.get("params") or {}).get("protocolVersion", DEFAULT_PROTOCOL),
            "capabilities": {"tools": {}},
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            "instructions": AUDIT_GUIDE,
        }
    elif method == "ping":
        result = {}
    elif method == "tools/list":
        result = {"tools": TOOLS}
    elif method == "tools/call":
        params = msg.get("params") or {}
        try:
            text, is_error = _call_tool(params.get("name", ""), params.get("arguments") or {}), False
        except Exception as exc:  # el error vuelve a Claude como resultado, no rompe la sesion
            text, is_error = str(exc), True
        result = {"content": [{"type": "text", "text": text}], "isError": is_error}
    else:
        return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32601, "message": f"Metodo no soportado: {method}"}}
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            response = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "JSON invalido"}}
        else:
            response = _handle(msg)
        if response is not None:
            sys.stdout.write(json.dumps(response, ensure_ascii=False) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stdin.reconfigure(encoding="utf-8")
    main()
