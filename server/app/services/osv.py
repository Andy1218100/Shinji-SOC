"""Cliente minimo de OSV.dev (https://osv.dev) -- base de datos de
vulnerabilidades abierta, mantenida por Google, sin necesidad de cuenta
ni API key. Es la unica fuente de verdad sobre si un paquete tiene una
vulnerabilidad conocida: la IA nunca decide esto por su cuenta, solo
redacta la recomendacion a partir de lo que OSV devuelve.
"""

import httpx

OSV_API = "https://api.osv.dev/v1"


async def query_batch(packages: list[tuple[str, str]], ecosystem: str = "Debian") -> list[list[str]]:
    """Para cada (nombre, version), devuelve la lista de IDs de
    vulnerabilidad (CVE/GHSA/DSA) que OSV conoce para esa version."""

    if not packages:
        return []

    queries = [{"package": {"name": name, "ecosystem": ecosystem}, "version": version} for name, version in packages]

    async with httpx.AsyncClient(timeout=60) as client:
        resp = await client.post(f"{OSV_API}/querybatch", json={"queries": queries})
        resp.raise_for_status()
        results = resp.json().get("results", [])

    return [[v["id"] for v in (r.get("vulns") or [])] for r in results]


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


def extract_fixed_version(vuln: dict, package_name: str) -> str | None:
    for affected in vuln.get("affected", []):
        if affected.get("package", {}).get("name") != package_name:
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
