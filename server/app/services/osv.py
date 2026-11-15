"""Cliente minimo de OSV.dev (https://osv.dev) -- base de datos de
vulnerabilidades abierta, mantenida por Google, sin necesidad de cuenta
ni API key. Es la unica fuente de verdad sobre si un paquete tiene una
vulnerabilidad conocida: la IA nunca decide esto por su cuenta, solo
redacta la recomendacion a partir de lo que OSV devuelve.
"""

import httpx

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


async def get_vuln(vuln_id: str) -> dict:
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(f"{OSV_API}/vulns/{vuln_id}")
        resp.raise_for_status()
        return resp.json()


def extract_severity(vuln: dict) -> str:
    db_severity = (vuln.get("database_specific") or {}).get("severity", "")
    if db_severity.upper() in ("CRITICAL", "HIGH"):
        return "critical"
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
