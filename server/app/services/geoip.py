"""Resolucion de IP a geolocalizacion usando una base MaxMind GeoLite2-City local.

Si el archivo .mmdb no existe (porque el usuario no configuro su license
key de MaxMind todavia), las funciones devuelven None sin fallar: el resto
del sistema sigue funcionando, solo que sin coordenadas en el mapa.
"""

import logging
import os
from functools import lru_cache

from app.core.config import settings

logger = logging.getLogger("geoip")

_PRIVATE_PREFIXES = ("10.", "127.", "192.168.", "172.16.", "172.17.", "172.18.")


class GeoResult:
    def __init__(self, country: str | None, city: str | None, lat: float | None, lon: float | None):
        self.country = country
        self.city = city
        self.lat = lat
        self.lon = lon


@lru_cache(maxsize=1)
def _reader():
    if not os.path.exists(settings.geoip_db_path):
        logger.warning(
            "No se encontro %s. Configura MAXMIND_LICENSE_KEY y corre scripts/update_geoip_db.sh",
            settings.geoip_db_path,
        )
        return None

    import geoip2.database

    return geoip2.database.Reader(settings.geoip_db_path)


def is_configured() -> bool:
    return os.path.exists(settings.geoip_db_path)


def lookup(ip: str) -> GeoResult:
    if any(ip.startswith(p) for p in _PRIVATE_PREFIXES) or ip in ("localhost", "::1"):
        return GeoResult(None, None, None, None)

    reader = _reader()
    if reader is None:
        return GeoResult(None, None, None, None)

    try:
        resp = reader.city(ip)
        return GeoResult(
            country=resp.country.name,
            city=resp.city.name,
            lat=resp.location.latitude,
            lon=resp.location.longitude,
        )
    except Exception:
        return GeoResult(None, None, None, None)
