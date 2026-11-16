"""Configuracion editable desde la pagina /settings.

El .env del proyecto sigue siendo la unica fuente de verdad: la pagina lo
reescribe (montado en el contenedor, ver docker-compose.yml) y ademas
aplica el valor en caliente sobre `settings`, asi no hace falta reiniciar.
Lo usan tambien el servidor MCP de auditoria (AUDIT_API_TOKEN) y
scripts/update_geoip_db.sh (MAXMIND_*), que leen el mismo archivo.

Solo se puede editar lo del catalogo. Quedan afuera a proposito los valores
de infraestructura (POSTGRES_*, DATABASE_URL, OLLAMA_HOST): mal puestos
desde la pagina dejan la plataforma sin base de datos o sin IA, sin forma
de arreglarlo desde la misma pagina.
"""

import io
import os
import re
import secrets
import tarfile
from dataclasses import dataclass
from pathlib import Path

import httpx

from app.core.config import settings

ENV_FILE = Path(os.environ.get("PROX_SECURE_ENV_FILE", "/config/.env"))
APPENDED_HEADER = "# Configurado desde la pagina de Prox Secure"


@dataclass(frozen=True)
class Field:
    key: str
    attr: str
    label: str
    group: str
    kind: str  # str | int | bool | choice | secret
    help: str
    choices: tuple[str, ...] = ()
    min: int | None = None
    max: int | None = None
    applies: str = "Inmediato"
    optional: bool = False  # str que puede quedar vacio


CATALOG: tuple[Field, ...] = (
    Field("AI_BACKEND", "ai_backend", "Motor de IA", "Inteligencia artificial", "choice",
          "Ollama corre en este servidor, sin enviar datos afuera. Claude usa la API de Anthropic y necesita una API key.",
          choices=("ollama", "claude")),
    Field("OLLAMA_MODEL", "ollama_model", "Modelo de Ollama", "Inteligencia artificial", "str",
          "Tiene que estar descargado en Ollama (la lista muestra los que hay). En CPU, uno chico como qwen2.5:3b."),
    Field("CLAUDE_MODEL", "claude_model", "Modelo de Claude", "Inteligencia artificial", "str",
          "Solo se usa si el motor es Claude."),
    Field("ANTHROPIC_API_KEY", "anthropic_api_key", "API key de Anthropic", "Inteligencia artificial", "secret",
          "Solo hace falta para el motor Claude. La auditoria con Claude Code (MCP) no la necesita."),
    Field("AUDIT_API_TOKEN", "audit_api_token", "Token de auditoria (MCP)", "Auditoria externa", "secret",
          "Lo usa el servidor MCP de tools/mcp_audit, que lo lee de este mismo .env. Vacio = auditoria apagada."),
    Field("MAXMIND_ACCOUNT_ID", "maxmind_account_id", "MaxMind Account ID", "Mapa de ataques (GeoIP)", "str",
          "Cuenta gratuita en maxmind.com/en/geolite2/signup: el Account ID esta arriba a la izquierda de tu cuenta.",
          optional=True),
    Field("MAXMIND_LICENSE_KEY", "maxmind_license_key", "MaxMind License Key", "Mapa de ataques (GeoIP)", "secret",
          "En tu cuenta de MaxMind: Manage License Keys. Despues usa \"Descargar base GeoIP\"."),
    Field("NOTIFY_MIN_SEVERITY", "notify_min_severity", "Avisar eventos desde", "Notificaciones", "choice",
          "critical: solo lo grave (fuerza bruta contra root, login tras fallos, webshell). warning: tambien escaneos de rutas, que en un servidor expuesto son constantes.",
          choices=("critical", "warning")),
    Field("NOTIFY_VULNS", "notify_vulns", "Avisar vulnerabilidades con solucion", "Notificaciones", "bool",
          "Un mensaje por escaneo cuando aparecen CVEs nuevos que ya tienen version corregida (algo para actualizar). Los que no tienen parche no avisan."),
    Field("NOTIFY_INCLUDE_IPS", "notify_include_ips", "Incluir IPs de origen", "Notificaciones", "bool",
          "Los mensajes salen a Telegram, ntfy o tu servidor de correo. Apagado, solo dicen \"IP en el panel\" (minimizacion de datos)."),
    Field("NOTIFY_COOLDOWN_SECONDS", "notify_cooldown_seconds", "Minimo entre avisos iguales (segundos)", "Notificaciones", "int",
          "Un aviso por tipo de evento y host en este periodo: un ataque sostenido no manda cien mensajes.", min=60, max=86400),
    Field("TELEGRAM_BOT_TOKEN", "telegram_bot_token", "Telegram: token del bot", "Notificaciones", "secret",
          "Crea un bot hablando con @BotFather en Telegram; te da el token."),
    Field("TELEGRAM_CHAT_ID", "telegram_chat_id", "Telegram: chat ID", "Notificaciones", "str",
          "Tu ID numerico (te lo da @userinfobot) o el de un grupo. Escribile algo al bot antes, si no no te puede escribir.",
          optional=True),
    Field("NTFY_URL", "ntfy_url", "ntfy: URL del tema", "Notificaciones", "str",
          "Ej. https://ntfy.sh/un-nombre-dificil-de-adivinar (en ntfy.sh publico, quien sepa el tema lee los mensajes) o tu propio servidor ntfy.",
          optional=True),
    Field("NTFY_TOKEN", "ntfy_token", "ntfy: token de acceso", "Notificaciones", "secret",
          "Solo si el tema esta protegido (tk_...)."),
    Field("SMTP_HOST", "smtp_host", "Correo: servidor SMTP", "Notificaciones", "str", "Ej. smtp.gmail.com.", optional=True),
    Field("SMTP_PORT", "smtp_port", "Correo: puerto", "Notificaciones", "int", "587 con STARTTLS, 465 con TLS directo.", min=1, max=65535),
    Field("SMTP_STARTTLS", "smtp_starttls", "Correo: usar STARTTLS", "Notificaciones", "bool", "Dejalo activado salvo que tu servidor no lo soporte (en 465 no se usa)."),
    Field("SMTP_USER", "smtp_user", "Correo: usuario", "Notificaciones", "str", "Vacio si el servidor no pide login.", optional=True),
    Field("SMTP_PASSWORD", "smtp_password", "Correo: contrasena", "Notificaciones", "secret", "En Gmail, una contrasena de aplicacion, no la de la cuenta."),
    Field("SMTP_FROM", "smtp_from", "Correo: remitente", "Notificaciones", "str", "Direccion desde la que sale el aviso.", optional=True),
    Field("SMTP_TO", "smtp_to", "Correo: destinatario", "Notificaciones", "str", "A quien le llegan los avisos (varias separadas por coma).", optional=True),
    Field("IDS_WINDOW_SECONDS", "ids_window_seconds", "Ventana de deteccion (segundos)", "Deteccion de intrusos", "int",
          "Periodo en el que se cuentan las peticiones de una misma IP.", min=10, max=3600),
    Field("IDS_REQUESTS_THRESHOLD", "ids_requests_threshold", "Peticiones para marcar fuerza bruta", "Deteccion de intrusos", "int",
          "Peticiones de una misma IP dentro de la ventana para generar un evento.", min=5, max=100000),
    Field("IDS_404_THRESHOLD", "ids_404_threshold", "Errores 404 para marcar escaneo", "Deteccion de intrusos", "int",
          "Respuestas 404 a una misma IP dentro de la ventana para generar un evento.", min=3, max=100000),
    Field("SSH_FAIL_THRESHOLD", "ssh_fail_threshold", "Logins fallidos para marcar fuerza bruta", "Deteccion de intrusos", "int",
          "Intentos fallidos de SSH o de la web de Proxmox desde una misma IP, dentro de la ventana de logins.", min=3, max=1000),
    Field("SSH_WINDOW_SECONDS", "ssh_window_seconds", "Ventana de logins (segundos)", "Deteccion de intrusos", "int",
          "Periodo en el que se cuentan los logins fallidos de una misma IP. 600 = 10 minutos.", min=60, max=86400),
    Field("VULN_SCAN_INTERVAL_SECONDS", "vuln_scan_interval_seconds", "Escaneo de vulnerabilidades (segundos)", "Escaneos y alertas", "int",
          "Cada cuanto se revisan todos los hosts (ademas de cada inventario nuevo). 86400 = una vez al dia.",
          min=3600, max=604800, applies="Desde el proximo ciclo"),
    Field("ALERT_EVAL_INTERVAL_SECONDS", "alert_eval_interval_seconds", "Evaluacion de alertas (segundos)", "Escaneos y alertas", "int",
          "Cada cuanto se comparan las metricas con las reglas de alerta.", min=10, max=3600, applies="Desde el proximo ciclo"),
    Field("SESSION_MAX_AGE_SECONDS", "session_max_age_seconds", "Duracion de la sesion (segundos)", "Sesiones y acceso", "int",
          "Despues de este tiempo hay que volver a iniciar sesion. 86400 = 24 horas.", min=300, max=2592000),
    Field("SESSION_COOKIE_SECURE", "session_cookie_secure", "Cookies solo por HTTPS", "Sesiones y acceso", "bool",
          "Activalo solo si el panel se usa por HTTPS: por HTTP no vas a poder iniciar sesion.",
          applies="Desde el proximo inicio de sesion"),
    Field("LOGIN_MAX_ATTEMPTS", "login_max_attempts", "Intentos de inicio de sesion", "Sesiones y acceso", "int",
          "Intentos fallidos antes de bloquear temporalmente la cuenta.", min=3, max=20),
    Field("LOGIN_LOCKOUT_SECONDS", "login_lockout_seconds", "Bloqueo tras fallar (segundos)", "Sesiones y acceso", "int",
          "Cuanto dura el bloqueo despues de agotar los intentos.", min=60, max=86400),
)
BY_KEY = {f.key: f for f in CATALOG}
# Se generan con un boton, no se escriben a mano.
GENERATED = {"AUDIT_API_TOKEN": 32, "SESSION_SECRET_KEY": 48}
READ_ONLY_KEYS = ("POSTGRES_USER", "POSTGRES_PASSWORD", "POSTGRES_DB", "DATABASE_URL", "OLLAMA_HOST")

_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$")
_SAFE_VALUE = re.compile(r"^[A-Za-z0-9_\-.:/@+=,]*$")


def env_file_available() -> bool:
    return ENV_FILE.is_file() and os.access(ENV_FILE, os.W_OK)


def _unquote(raw: str) -> str:
    raw = raw.strip()
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "\"'":
        inner = raw[1:-1]
        return inner.replace('\\"', '"').replace("\\\\", "\\") if raw[0] == '"' else inner
    return raw


def read_env_file() -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
            m = _LINE.match(line)
            if m and not line.lstrip().startswith("#"):
                values[m.group(1)] = _unquote(m.group(2))
    except OSError:
        pass
    return values


def _quote(value: str) -> str:
    if _SAFE_VALUE.match(value):
        return value
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def write_env_values(updates: dict[str, str]) -> None:
    """Actualiza las lineas KEY=... existentes (conservando comentarios y
    orden) y agrega al final las que no estaban. Escribe en el mismo archivo
    (no rename): es un bind mount de un solo archivo y no se puede reemplazar."""
    text = ENV_FILE.read_text(encoding="utf-8")
    lines = text.splitlines()
    pending = dict(updates)
    out = []
    for line in lines:
        m = _LINE.match(line)
        if m and not line.lstrip().startswith("#") and m.group(1) in pending:
            key = m.group(1)
            out.append(f"{key}={_quote(pending.pop(key))}")
        elif m and not line.lstrip().startswith("#") and m.group(1) in updates:
            continue  # duplicado de una clave ya escrita: se descarta
        else:
            out.append(line)
    if pending:
        if APPENDED_HEADER not in out:
            out += ["", APPENDED_HEADER]
        out += [f"{k}={_quote(v)}" for k, v in pending.items()]
    content = "\n".join(out) + "\n"
    with open(ENV_FILE, "r+", encoding="utf-8", newline="\n") as fh:
        fh.seek(0)
        fh.write(content)
        fh.truncate()
        fh.flush()
        os.fsync(fh.fileno())


def parse(field: Field, raw) -> object:
    """Valida y convierte lo que llega de la pagina. ValueError con un
    mensaje para mostrar si no sirve."""
    if field.kind == "bool":
        if isinstance(raw, bool):
            return raw
        if str(raw).lower() in ("true", "1", "si", "on"):
            return True
        if str(raw).lower() in ("false", "0", "no", "off", ""):
            return False
        raise ValueError(f"{field.label}: tiene que ser si o no")
    value = "" if raw is None else str(raw).strip()
    if "\n" in value or "\r" in value:
        raise ValueError(f"{field.label}: no puede tener saltos de linea")
    if len(value) > 500:
        raise ValueError(f"{field.label}: demasiado largo")
    if field.kind == "int":
        try:
            number = int(value)
        except ValueError:
            raise ValueError(f"{field.label}: tiene que ser un numero entero") from None
        if field.min is not None and number < field.min or field.max is not None and number > field.max:
            raise ValueError(f"{field.label}: tiene que estar entre {field.min} y {field.max}")
        return number
    if field.kind == "choice" and value not in field.choices:
        raise ValueError(f"{field.label}: opcion invalida")
    if field.kind == "str" and not field.optional and not value:
        raise ValueError(f"{field.label}: no puede quedar vacio")
    if field.key == "NTFY_URL" and value and not value.startswith(("https://", "http://")):
        raise ValueError(f"{field.label}: tiene que empezar con https://")
    if field.key in ("SMTP_FROM", "SMTP_TO") and value and "@" not in value:
        raise ValueError(f"{field.label}: no parece una direccion de correo")
    if field.key == "MAXMIND_ACCOUNT_ID" and value and not value.isdigit():
        raise ValueError(f"{field.label}: es un numero")
    return value


def serialize(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def apply(field: Field, value) -> None:
    setattr(settings, field.attr, value)


def load_from_env_file() -> None:
    """Al arrancar: el .env montado manda sobre las variables de entorno del
    contenedor, que compose fijo al crearlo y pueden estar desactualizadas
    (un cambio desde la pagina no las toca; `docker compose restart` no
    vuelve a leer el env_file)."""
    values = read_env_file()
    for key, raw in values.items():
        field = BY_KEY.get(key)
        if field:
            try:
                apply(field, parse(field, raw) if field.kind != "secret" else raw)
            except ValueError:
                continue
    if values.get("SESSION_SECRET_KEY"):
        settings.session_secret_key = values["SESSION_SECRET_KEY"]


def _source(key: str, file_values: dict) -> str:
    if key in file_values:
        return ".env"
    if key in os.environ:
        return "entorno del contenedor"
    return "valor por defecto"


def public_view() -> dict:
    file_values = read_env_file()
    fields = []
    for f in CATALOG:
        value = getattr(settings, f.attr, None)
        item = {
            "key": f.key, "label": f.label, "group": f.group, "kind": f.kind, "help": f.help,
            "choices": list(f.choices), "min": f.min, "max": f.max, "applies": f.applies,
            "source": _source(f.key, file_values), "generable": f.key in GENERATED,
        }
        if f.kind == "secret":
            # Nunca se devuelve un secreto al navegador: solo si esta y sus
            # ultimos caracteres para reconocerlo.
            item["configured"] = bool(value)
            item["hint"] = f"termina en {str(value)[-4:]}" if value and len(str(value)) >= 12 else ("configurada" if value else "")
            item["value"] = None
        else:
            item["value"] = value
        fields.append(item)
    return {
        "env_file": str(ENV_FILE),
        "env_file_available": env_file_available(),
        "fields": fields,
        "read_only": list(READ_ONLY_KEYS),
        "geoip": {"configured": os.path.exists(settings.geoip_db_path),
                  "updated": os.path.getmtime(settings.geoip_db_path) if os.path.exists(settings.geoip_db_path) else None},
    }


def update(values: dict) -> list[str]:
    """Valida todo antes de escribir nada. Devuelve las claves cambiadas."""
    parsed = {}
    for key, raw in values.items():
        field = BY_KEY.get(key)
        if field is None:
            raise ValueError(f"{key} no se puede cambiar desde la pagina")
        parsed[key] = (field, raw.strip() if field.kind == "secret" and isinstance(raw, str) else parse(field, raw))
        if field.kind == "secret" and ("\n" in str(raw) or len(str(raw)) > 500):
            raise ValueError(f"{field.label}: valor invalido")

    backend = parsed.get("AI_BACKEND", (None, settings.ai_backend))[1]
    api_key = parsed["ANTHROPIC_API_KEY"][1] if "ANTHROPIC_API_KEY" in parsed else settings.anthropic_api_key
    if backend == "claude" and not api_key:
        raise ValueError("Para usar Claude como motor hace falta la API key de Anthropic")

    write_env_values({k: serialize(v) for k, (_, v) in parsed.items()})
    for _, (field, value) in parsed.items():
        apply(field, value)
    return list(parsed)


def generate(key: str) -> None:
    """Genera un secreto nuevo (token de auditoria o clave de sesion), lo
    guarda en el .env y lo aplica. No se devuelve: el MCP lo lee del .env."""
    if key not in GENERATED:
        raise ValueError(f"{key} no se genera automaticamente")
    value = secrets.token_urlsafe(GENERATED[key])
    write_env_values({key: value})
    if key == "SESSION_SECRET_KEY":
        settings.session_secret_key = value
    else:
        apply(BY_KEY[key], value)


async def ollama_models() -> list[str]:
    async with httpx.AsyncClient(base_url=settings.ollama_host, timeout=10) as client:
        resp = await client.get("/api/tags")
        resp.raise_for_status()
        return sorted(m["name"] for m in resp.json().get("models", []))


async def download_geoip() -> None:
    """Igual que scripts/update_geoip_db.sh, desde el servidor: MaxMind pide
    Account ID + License Key por HTTP Basic Auth."""
    from app.services import geoip

    account = getattr(settings, "maxmind_account_id", None)
    key = settings.maxmind_license_key
    if not account or not key:
        raise ValueError("Primero guarda el Account ID y la License Key de MaxMind")
    async with httpx.AsyncClient(timeout=120, follow_redirects=True) as client:
        resp = await client.get(
            "https://download.maxmind.com/geoip/databases/GeoLite2-City/download?suffix=tar.gz",
            auth=(str(account), str(key)),
        )
    if resp.status_code == 401:
        raise ValueError("MaxMind rechazo el Account ID o la License Key")
    resp.raise_for_status()

    with tarfile.open(fileobj=io.BytesIO(resp.content), mode="r:gz") as tar:
        member = next((m for m in tar.getmembers() if m.isfile() and m.name.endswith("/GeoLite2-City.mmdb")), None)
        if member is None:
            raise ValueError("La descarga de MaxMind no trae GeoLite2-City.mmdb")
        data = tar.extractfile(member).read()

    target = Path(settings.geoip_db_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(".mmdb.tmp")
    tmp.write_bytes(data)
    os.replace(tmp, target)
    geoip._reader.cache_clear()
