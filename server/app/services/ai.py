import logging
import re

import httpx

from app.core.config import settings

logger = logging.getLogger("ai")

SYSTEM_PROMPT = (
    "Eres un asistente de monitoreo de infraestructura. Recibes metricas y alertas "
    "de servidores y debes responder de forma breve, concreta y en espanol, "
    "senalando la causa probable y una accion recomendada cuando aplique."
)


# Sin tope, un modelo chico a veces "degenera" y sigue generando texto
# basura (mezcla de idiomas, fragmentos de codigo) hasta llenar el contexto
# o el timeout -- paso en un host real con la recomendacion de un paquete.
# Todas las respuestas que se piden son de pocas frases.
OLLAMA_OPTIONS = {"temperature": 0.3, "num_predict": 512}

ATTEMPTS = 2
# llama-server (el motor de Ollama) reutiliza el estado calculado del prompt
# anterior si el nuevo empieza igual. Si ese estado quedo corrupto (se vio:
# basura reproducible para un prompt hasta recalcularlo; la causa de fondo
# no esta identificada), repetir el mismo prompt devuelve la misma basura.
# Cambiar el comienzo del prompt de sistema obliga a recalcularlo desde cero.
RETRY_SYSTEM_PREFIX = "Responde con cuidado. "

CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
# Versiones tipo 3.0.4, 2:7.4-1+deb13u2, 1.21-1.
VERSION_RE = re.compile(r"\b\d+(?::\d+)?(?:\.\d+)+(?:[-+~][0-9A-Za-z.+~]*[0-9A-Za-z])?")


class AIOutputError(RuntimeError):
    """El modelo respondio, pero la respuesta no es usable."""


def looks_degenerate(text: str) -> bool:
    # Lo que no es latin (incluidos acentos) ni puntuacion tipografica comun:
    # CJK, cirilico, caracter de reemplazo, etc. En espanol deberia ser ~0.
    # No atrapa basura escrita solo en alfabeto latino; esa la corta el tope
    # de num_predict (la basura observada nunca terminaba sola).
    if not text:
        return False
    foreign = sum(1 for c in text if ord(c) > 0x024F and not 0x2000 <= ord(c) <= 0x206F)
    return foreign / len(text) > 0.02


def ungrounded_identifiers(text: str, source: str) -> list[str]:
    """CVEs y numeros de version que la respuesta menciona y el prompt no:
    un modelo chico puede inventarlos aunque se le pida que no. Comparacion
    por subcadena: "CVE-2011-3374" esta en "DEBIAN-CVE-2011-3374" y "7.4"
    en "2:7.4-1+deb13u2"."""
    source_lower = source.lower()
    found = CVE_RE.findall(text) + VERSION_RE.findall(text)
    return [tok for tok in dict.fromkeys(found) if tok.lower() not in source_lower]


async def ask_ollama(prompt: str, retry: bool = False) -> str:
    system = RETRY_SYSTEM_PREFIX + SYSTEM_PROMPT if retry else SYSTEM_PROMPT
    async with httpx.AsyncClient(base_url=settings.ollama_host, timeout=120) as client:
        resp = await client.post(
            "/api/chat",
            json={
                "model": settings.ollama_model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt},
                ],
                "stream": False,
                "options": OLLAMA_OPTIONS,
            },
        )
        resp.raise_for_status()
        data = resp.json()
    text = data.get("message", {}).get("content", "").strip()
    snippet = repr(text[:120])
    if data.get("done_reason") == "length":
        raise AIOutputError(f"la respuesta llego al tope de tokens sin terminar (probable degeneracion): {snippet}")
    if looks_degenerate(text):
        raise AIOutputError(f"la respuesta tiene texto en otros alfabetos (probable degeneracion): {snippet}")
    return text


async def ask_claude(prompt: str) -> str:
    if not settings.anthropic_api_key:
        raise RuntimeError("ANTHROPIC_API_KEY no configurada")

    from anthropic import AsyncAnthropic

    client = AsyncAnthropic(api_key=settings.anthropic_api_key)
    message = await client.messages.create(
        model=settings.claude_model,
        max_tokens=1024,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": prompt}],
    )
    return "".join(block.text for block in message.content if block.type == "text").strip()


async def ask(prompt: str, backend: str | None = None, grounded: bool = False) -> str:
    """grounded=True rechaza respuestas que citan CVEs o versiones que no
    estan en el prompt. Una respuesta invalida se reintenta una vez,
    recalculando el prompt desde cero (ver RETRY_SYSTEM_PREFIX); los datos
    inventados salen del muestreo y otra muestra suele salir bien. Si las
    dos fallan, AIOutputError."""
    backend = backend or settings.ai_backend
    for attempt in range(1, ATTEMPTS + 1):
        try:
            text = await (ask_claude(prompt) if backend == "claude" else ask_ollama(prompt, retry=attempt > 1))
            if grounded and (invented := ungrounded_identifiers(text, prompt)):
                raise AIOutputError(f"la respuesta cita datos que no estan en el prompt: {', '.join(invented)}")
            return text
        except AIOutputError as exc:
            logger.warning("Respuesta de IA invalida (intento %d/%d): %s", attempt, ATTEMPTS, exc)
            if attempt == ATTEMPTS:
                raise
    raise AssertionError("inalcanzable")
