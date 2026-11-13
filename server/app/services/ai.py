import httpx

from app.core.config import settings

SYSTEM_PROMPT = (
    "Eres un asistente de monitoreo de infraestructura. Recibes metricas y alertas "
    "de servidores y debes responder de forma breve, concreta y en espanol, "
    "senalando la causa probable y una accion recomendada cuando aplique."
)


async def ask_ollama(prompt: str) -> str:
    async with httpx.AsyncClient(base_url=settings.ollama_host, timeout=120) as client:
        resp = await client.post(
            "/api/chat",
            json={
                "model": settings.ollama_model,
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                "stream": False,
            },
        )
        resp.raise_for_status()
        return resp.json().get("message", {}).get("content", "").strip()


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


async def ask(prompt: str, backend: str | None = None) -> str:
    backend = backend or settings.ai_backend
    if backend == "claude":
        return await ask_claude(prompt)
    return await ask_ollama(prompt)
