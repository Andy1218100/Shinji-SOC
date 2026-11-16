"""Cliente minimo de OSV.dev (https://osv.dev) -- base de datos de
vulnerabilidades abierta, mantenida por Google, sin necesidad de cuenta
ni API key. Es la unica fuente de verdad sobre si un paquete tiene una
vulnerabilidad conocida: la IA nunca decide esto por su cuenta, solo
redacta la recomendacion a partir de lo que OSV devuelve.
"""

import asyncio
import logging

import httpx

logger = logging.getLogger("osv")

OSV_API = "https://api.osv.dev/v1"
# Mas de 1000 por request -> 400 "too many queries" (medido contra la API
# real; un host Proxmox tipico ya tiene ~1500 paquetes).
BATCH_MAX = 1000


async def query_batch(packages: list[tuple[str, str]], ecosystem: str = "Debian") -> list[list[str]]:
    """Para cada (nombre, version), devuelve la lista de IDs de
    vulnerabilidad (CVE/GHSA/DSA) que OSV conoce para esa version."""

    queries = [{"package": {"name": name, "ecosystem": ecosystem}, "version": version} for name, version in packages]
    found: list[list[str]] = [[] for _ in queries]

    async with httpx.AsyncClient(timeout=60) as client:
        for start in range(0, len(queries), BATCH_MAX):
            # indice global -> query; se achica a las que devolvieron
            # next_page_token (paginacion por query, ver docs de querybatch).
            pending = {start + i: q for i, q in enumerate(queries[start:start + BATCH_MAX])}
            while pending:
                idxs = list(pending)
                resp = await client.post(f"{OSV_API}/querybatch", json={"queries": [pending[i] for i in idxs]})
                resp.raise_for_status()
                results = resp.json().get("results", [])
                next_pending = {}
                for idx, r in zip(idxs, results):
                    found[idx].extend(v["id"] for v in (r.get("vulns") or []))
                    if r.get("next_page_token"):
                        next_pending[idx] = {**queries[idx], "page_token": r["next_page_token"]}
                pending = next_pending

    return found


# Pedidos de detalle simultaneos. OSV es un servicio publico y gratuito:
# pocos en paralelo, con reintento si responde 429 o 5xx.
DETAIL_CONCURRENCY = 8


async def get_vulns(vuln_ids, concurrency: int = DETAIL_CONCURRENCY) -> dict[str, dict]:
    """Detalle de varios advisories reutilizando una conexion. Antes se
    pedian de a uno y cada pedido abria una conexion TLS nueva: con ~1100
    CVEs "sin evaluar" en un Proxmox, el escaneo tardaba mas de 10 minutos.
    Los que fallan tras los reintentos no estan en el resultado."""
    sem = asyncio.Semaphore(concurrency)
    out: dict[str, dict] = {}

    async def one(client: httpx.AsyncClient, vid: str) -> None:
        async with sem:
            for attempt in range(1, 4):
                try:
                    resp = await client.get(f"{OSV_API}/vulns/{vid}")
                    if resp.status_code == 429 or resp.status_code >= 500:
                        await asyncio.sleep(attempt)
                        continue
                    resp.raise_for_status()
                    out[vid] = resp.json()
                    return
                except httpx.HTTPError:
                    await asyncio.sleep(attempt)
            logger.warning("No se pudo obtener el detalle de %s", vid)

    async with httpx.AsyncClient(timeout=30) as client:
        await asyncio.gather(*(one(client, vid) for vid in dict.fromkeys(vuln_ids)))
    return out


async def get_vuln(vuln_id: str) -> dict:
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(f"{OSV_API}/vulns/{vuln_id}")
        resp.raise_for_status()
        return resp.json()


UNIMPORTANT = "unimportant"
# Urgencias que Debian puede cambiar al hacer triage: se vuelven a consultar.
PROVISIONAL_URGENCIES = {None, "not yet assigned"}


def extract_urgency(vuln: dict, package_name: str, ecosystem: str) -> str | None:
    """Urgencia que asigno el tracker de seguridad de Debian (unimportant,
    low, medium, high, not yet assigned). Los avisos DEBIAN-CVE-* no traen
    database_specific.severity: sin esto todos salian "warning" y no habia
    forma de separar los 174 "unimportant" de un host real (binutils:
    "not covered by security support") del resto."""
    for affected in vuln.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("name") == package_name and pkg.get("ecosystem") == ecosystem:
            urgency = (affected.get("ecosystem_specific") or {}).get("urgency")
            # El tracker a veces agrega marcas como "low**"; solo la palabra.
            return urgency.strip().rstrip("*").strip().lower() if urgency else None
    return None


def extract_severity(vuln: dict, urgency: str | None = None) -> str:
    db_severity = (vuln.get("database_specific") or {}).get("severity", "")
    if db_severity.upper() in ("CRITICAL", "HIGH") or urgency == "high":
        return "critical"
    if urgency == UNIMPORTANT:
        return "info"
    return "warning"


def extract_fixed_version(vuln: dict, package_name: str, ecosystem: str) -> str | None:
    # Un mismo advisory trae un bloque "affected" por release (Debian:12,
    # Debian:13, ...) con su propio fix; el de otra release no sirve y puede
    # existir aunque la del host todavia no tenga parche.
    for affected in vuln.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("name") != package_name or pkg.get("ecosystem") != ecosystem:
            continue
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    return event["fixed"]
    return None


def extract_source_url(vuln: dict) -> str | None:
    for ref in vuln.get("references", []):
        if ref.get("type") == "ADVISORY":
            return ref.get("url")
    refs = vuln.get("references") or []
    if refs:
        return refs[0].get("url")
    return f"https://osv.dev/vulnerability/{vuln.get('id')}"
