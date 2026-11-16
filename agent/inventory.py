"""Inventario de paquetes instalados (dpkg), para que el servidor pueda
cruzarlo contra OSV.dev y detectar software con vulnerabilidades
conocidas. Solo funciona en sistemas basados en Debian/Ubuntu (como el
resto de este agente: fail2ban, apt, etc.).
"""

import logging
import subprocess

logger = logging.getLogger("inventory")


# ${source:Package}/${source:Version}: OSV indexa los avisos de Debian por
# paquete FUENTE. Consultando el binario, libssl3t64 devolvia 0 avisos y su
# fuente openssl 294 (medido); libc6 (fuente glibc) tampoco se revisaba.
# La version fuente tampoco es la del binario: bash 5.2.37-2+b10 viene del
# fuente 5.2.37-2, y bsdutils 1:2.41.5-... de util-linux 2.41.5-... (sin epoca).
DPKG_FORMAT = "${db:Status-Abbrev}\t${Package}\t${Version}\t${source:Package}\t${source:Version}\n"


def collect() -> list[dict]:
    try:
        result = subprocess.run(
            ["dpkg-query", "-W", f"-f={DPKG_FORMAT}"],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        logger.warning("dpkg-query no disponible; este host no parece ser Debian/Ubuntu, salteando inventario")
        return []

    # dict por nombre: con multiarch (amd64 + i386) dpkg lista el mismo
    # paquete una vez por arquitectura.
    packages: dict[str, dict] = {}
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) != 5:
            continue
        status, name, version, source_name, source_version = (p.strip() for p in parts)
        # "ii" = instalado. Los "rc" (desinstalados con config residual)
        # no tienen el binario y darian falsos positivos de CVE.
        if status != "ii":
            continue
        packages[name] = {
            "name": name,
            "version": version,
            "source_name": source_name or name,
            "source_version": source_version or version,
        }

    return list(packages.values())


def debian_release() -> str | None:
    """VERSION_ID de /etc/os-release (ej. "11" para bullseye, "12" para
    bookworm). Necesario para consultar OSV.dev con el ecosistema
    correcto (Debian:11, Debian:12, ...), no solo "Debian" a secas."""
    try:
        with open("/etc/os-release", "r", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("VERSION_ID="):
                    return line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    return None
