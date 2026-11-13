"""Inventario de paquetes instalados (dpkg), para que el servidor pueda
cruzarlo contra OSV.dev y detectar software con vulnerabilidades
conocidas. Solo funciona en sistemas basados en Debian/Ubuntu (como el
resto de este agente: fail2ban, apt, etc.).
"""

import logging
import subprocess

logger = logging.getLogger("inventory")


def collect() -> list[dict]:
    try:
        result = subprocess.run(
            ["dpkg-query", "-W", "-f=${Package}\t${Version}\n"],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        logger.warning("dpkg-query no disponible; este host no parece ser Debian/Ubuntu, salteando inventario")
        return []

    packages = []
    for line in result.stdout.splitlines():
        if "\t" not in line:
            continue
        name, version = line.split("\t", 1)
        packages.append({"name": name.strip(), "version": version.strip()})

    return packages


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
