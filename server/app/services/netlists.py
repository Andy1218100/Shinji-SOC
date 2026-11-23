"""Listas de redes: proxies (Cloudflare y los que configure el admin) y
redes maliciosas conocidas (Spamhaus DROP).

- Proxies: detras de Cloudflare o de un tunel, la IP que llega al servidor
  web es la del proxy, no la del visitante (Cloudflare: "a Cloudflare IP
  address is logged by default"). Bloquear esa IP no frena al atacante y
  corta trafico legitimo; la IP real, si el log la trae, va en
  CF-Connecting-IP / X-Forwarded-For y solo se le cree cuando la conexion
  viene de un proxy (si no, cualquiera puede inventarla).
- Spamhaus DROP: redes "leased or stolen by professional spam or
  cyber-crime operations". Gratis, descarga automatica como mucho una vez
  por hora (lo normal, una vez al dia) y con credito a The Spamhaus
  Project (https://www.spamhaus.org/drop/terms/).

Las listas se actualizan una vez al dia en segundo plano. Si la descarga de
Cloudflare falla se usan los rangos incluidos abajo (publicados en
cloudflare.com/ips el 2026-11-23).
"""

import asyncio
import ipaddress
import json
import logging
from datetime import datetime, timezone

import httpx

from app.core.config import settings

logger = logging.getLogger("netlists")

REFRESH_SECONDS = 86400
CLOUDFLARE_URLS = ("https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6")
DROP_URLS = ("https://www.spamhaus.org/drop/drop_v4.json", "https://www.spamhaus.org/drop/drop_v6.json")
DROP_CREDIT = "Spamhaus DROP (The Spamhaus Project)"

CLOUDFLARE_FALLBACK = (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
    "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
    "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32",
    "2a06:98c0::/29", "2c0f:f248::/32",
)

_cloudflare: list = [ipaddress.ip_network(n) for n in CLOUDFLARE_FALLBACK]
_drop: list[tuple] = []          # (red, sblid)
_drop_updated: str | None = None
_trusted_cache: tuple[str, list] = ("", [])


def parse_ip(value: str | None):
    """IP de un texto de log: sin corchetes, puerto ni zona; las IPv4
    mapeadas en IPv6 (::ffff:1.2.3.4) vuelven a IPv4. None si no es una IP."""
    if not value:
        return None
    text = value.strip().strip('"')
    if text.startswith("[") and "]" in text:
        text = text[1:text.index("]")]
    elif text.count(":") == 1:  # 1.2.3.4:5678
        text = text.split(":")[0]
    text = text.split("%")[0]
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return None
    if ip.version == 6 and ip.ipv4_mapped:
        return ip.ipv4_mapped
    return ip


def _networks(text: str) -> list:
    nets = []
    for item in text.replace(";", ",").replace(" ", ",").split(","):
        item = item.strip()
        if not item:
            continue
        try:
            nets.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            logger.warning("Proxy de confianza invalido en TRUSTED_PROXIES: %s", item)
    return nets


def _trusted() -> list:
    global _trusted_cache
    text = settings.trusted_proxies or ""
    if _trusted_cache[0] != text:
        _trusted_cache = (text, _networks(text))
    return _trusted_cache[1]


def _in(ip, nets) -> bool:
    return any(ip.version == n.version and ip in n for n in nets)


def is_cloudflare(value) -> bool:
    ip = parse_ip(str(value)) if not isinstance(value, (ipaddress.IPv4Address, ipaddress.IPv6Address)) else value
    return bool(ip) and _in(ip, _cloudflare)


def is_proxy(value) -> bool:
    """La IP es de Cloudflare o de un proxy/tunel configurado en
    TRUSTED_PROXIES (por defecto, solo la propia maquina)."""
    ip = parse_ip(str(value)) if not isinstance(value, (ipaddress.IPv4Address, ipaddress.IPv6Address)) else value
    return bool(ip) and (_in(ip, _cloudflare) or _in(ip, _trusted()))


def resolve_client(remote: str, forwarded: str | None) -> tuple[str, bool]:
    """(IP del cliente, detras_de_proxy_sin_ip_real).

    Si la conexion viene de un proxy y el log trae la IP real (primer valor
    de CF-Connecting-IP / X-Forwarded-For), se usa esa. Si viene de un proxy
    y no la trae, se devuelve la del proxy marcada como tal. Si no viene de
    un proxy, el valor reenviado se ignora: lo puede escribir cualquiera."""
    if not is_proxy(remote):
        return remote, False
    for candidate in (forwarded or "").split(","):
        ip = parse_ip(candidate)
        if ip and not is_proxy(ip):
            return str(ip), False
    return remote, True


def threat_match(value) -> str | None:
    """Nombre de la lista si la IP esta en una red maliciosa conocida."""
    if not settings.threat_intel_enabled or not _drop:
        return None
    ip = parse_ip(str(value))
    if not ip or not ip.is_global:
        return None
    for net, sblid in _drop:
        if ip.version == net.version and ip in net:
            return f"{DROP_CREDIT}, {sblid}" if sblid else DROP_CREDIT
    return None


def status() -> dict:
    return {"cloudflare_networks": len(_cloudflare), "drop_networks": len(_drop), "drop_updated": _drop_updated}


async def refresh() -> None:
    global _cloudflare, _drop, _drop_updated
    async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
        try:
            nets = []
            for url in CLOUDFLARE_URLS:
                resp = await client.get(url)
                resp.raise_for_status()
                nets += [ipaddress.ip_network(line.strip()) for line in resp.text.splitlines() if line.strip()]
            if len(nets) >= 10:  # una respuesta rara no deja al panel sin la lista
                _cloudflare = nets
        except Exception:
            logger.warning("No se pudo actualizar la lista de Cloudflare; se usa la anterior", exc_info=True)

        if not settings.threat_intel_enabled:
            return
        try:
            entries = []
            for url in DROP_URLS:
                resp = await client.get(url)
                resp.raise_for_status()
                for line in resp.text.splitlines():
                    if not line.strip():
                        continue
                    row = json.loads(line)
                    if "cidr" in row:
                        entries.append((ipaddress.ip_network(row["cidr"]), row.get("sblid")))
            if entries:
                _drop = entries
                _drop_updated = datetime.now(timezone.utc).isoformat()
                logger.info("Spamhaus DROP actualizada: %s redes", len(entries))
        except Exception:
            logger.warning("No se pudo actualizar Spamhaus DROP; se usa la anterior", exc_info=True)


async def run_forever() -> None:
    while True:
        await refresh()
        await asyncio.sleep(REFRESH_SECONDS)
