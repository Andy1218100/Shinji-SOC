"""Notificaciones por Telegram, ntfy y correo (SMTP).

Se configuran en la pagina de Configuracion; un canal sin datos no se usa.
Nunca levanta excepciones hacia quien avisa: una notificacion fallida no
debe cortar la deteccion ni el escaneo, solo queda en el log.

Los mensajes salen a servicios externos (Telegram, el servidor de ntfy, el
de correo): llevan lo minimo para actuar (host, tipo, severidad) y no las
IPs de origen salvo que se active NOTIFY_INCLUDE_IPS (criterio de
minimizacion pensado para la Ley 21.719; no es una opinion legal).

APIs: Telegram sendMessage (https://core.telegram.org/bots/api#sendmessage,
texto 1-4096) y ntfy (https://docs.ntfy.sh/publish/, cabeceras Title,
Priority 1-5 y Tags; token como "Authorization: Bearer tk_...").
"""

import asyncio
import logging
import smtplib
import ssl
import time
import unicodedata
from email.message import EmailMessage

import httpx

from app.core.config import settings

logger = logging.getLogger("notify")

SEVERITY_ORDER = {"info": 0, "warning": 1, "critical": 2}
_last_sent: dict[str, float] = {}


def channels() -> list[str]:
    out = []
    if settings.telegram_bot_token and settings.telegram_chat_id:
        out.append("telegram")
    if settings.ntfy_url:
        out.append("ntfy")
    if settings.smtp_host and settings.smtp_to and settings.smtp_from:
        out.append("correo")
    return out


def wants(severity: str) -> bool:
    return SEVERITY_ORDER.get(severity, 1) >= SEVERITY_ORDER.get(settings.notify_min_severity, 2)


def _cooldown_ok(key: str) -> bool:
    """Una notificacion por clave (p. ej. tipo de evento + host) cada
    NOTIFY_COOLDOWN_SECONDS: un ataque sostenido no debe mandar cien mensajes."""
    now = time.monotonic()
    last = _last_sent.get(key)
    if last is not None and now - last < settings.notify_cooldown_seconds:
        return False
    _last_sent[key] = now
    return True


async def _telegram(client: httpx.AsyncClient, title: str, body: str) -> None:
    resp = await client.post(
        f"https://api.telegram.org/bot{settings.telegram_bot_token}/sendMessage",
        json={"chat_id": settings.telegram_chat_id, "text": f"{title}\n\n{body}"[:4096]},
    )
    data = resp.json()
    if not data.get("ok"):
        raise RuntimeError(data.get("description") or f"HTTP {resp.status_code}")


async def _ntfy(client: httpx.AsyncClient, title: str, body: str, severity: str) -> None:
    # Las cabeceras HTTP van en ASCII: "·" -> "-" y se quitan los acentos
    # (sin esto llegaba "Shinji SOC ? prueba").
    ascii_title = unicodedata.normalize("NFKD", title.replace("·", "-")).encode("ascii", "ignore").decode()
    headers = {
        "Title": ascii_title,
        "Priority": {"critical": "5", "warning": "4"}.get(severity, "3"),
        "Tags": {"critical": "rotating_light", "warning": "warning"}.get(severity, "information_source"),
    }
    if settings.ntfy_token:
        headers["Authorization"] = f"Bearer {settings.ntfy_token}"
    resp = await client.post(settings.ntfy_url, content=body.encode("utf-8")[:4000], headers=headers)
    resp.raise_for_status()


def _smtp_send(title: str, body: str) -> None:
    msg = EmailMessage()
    msg["Subject"] = title
    msg["From"] = settings.smtp_from
    msg["To"] = settings.smtp_to
    msg.set_content(body)
    port = int(settings.smtp_port or 587)
    context = ssl.create_default_context()
    if port == 465:
        server = smtplib.SMTP_SSL(settings.smtp_host, port, timeout=20, context=context)
    else:
        server = smtplib.SMTP(settings.smtp_host, port, timeout=20)
        if settings.smtp_starttls:
            server.starttls(context=context)
    try:
        if settings.smtp_user:
            server.login(settings.smtp_user, settings.smtp_password or "")
        server.send_message(msg)
    finally:
        server.quit()


async def send(title: str, body: str, severity: str = "warning") -> dict[str, str]:
    """Manda por todos los canales configurados. Devuelve el resultado por
    canal ("ok" o el error) -- lo usa el boton de prueba."""
    results: dict[str, str] = {}
    active = channels()
    if not active:
        return results
    async with httpx.AsyncClient(timeout=20) as client:
        tasks = {}
        if "telegram" in active:
            tasks["telegram"] = _telegram(client, title, body)
        if "ntfy" in active:
            tasks["ntfy"] = _ntfy(client, title, body, severity)
        if "correo" in active:
            tasks["correo"] = asyncio.to_thread(_smtp_send, title, body)
        outcomes = await asyncio.gather(*tasks.values(), return_exceptions=True)
    for name, outcome in zip(tasks, outcomes):
        if isinstance(outcome, Exception):
            # Sin el token en el log: el error de httpx puede traer la URL de Telegram.
            message = str(outcome).replace(settings.telegram_bot_token or "\0", "***")[:200]
            logger.warning("Notificacion por %s fallo: %s", name, message)
            results[name] = message
        else:
            results[name] = "ok"
    return results


def notify_later(key: str, severity: str, title: str, body: str) -> None:
    """Para llamar desde la deteccion: filtra por severidad y enfriamiento y
    manda en segundo plano, sin demorar a quien avisa."""
    if not channels() or not wants(severity) or not _cooldown_ok(key):
        return
    asyncio.create_task(send(title, body, severity))


def ip_text(ip: str | None) -> str:
    if not ip or ip.startswith("local:"):
        return ""
    return f" desde {ip}" if settings.notify_include_ips else " (IP en el panel)"
