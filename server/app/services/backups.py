"""Estado de los respaldos que hace el contenedor "backup"
(scripts/backup_loop.sh) en /backups, y pedido de "Respaldar ahora".

El servidor no ejecuta pg_dump: el contenedor de respaldo usa la misma
imagen que la base, con su misma version de pg_dump. Para pedir un
respaldo, el servidor deja /backups/.request y el contenedor lo ve en
menos de 30 s (sin darle al servidor acceso al socket de Docker).
"""

import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path

from app.core.config import settings
from app.services import notify

logger = logging.getLogger("backups")

BACKUP_DIR = Path(os.environ.get("PROX_SECURE_BACKUP_DIR", "/backups"))
STALE_NOTIFY_EVERY_SECONDS = 86400
_last_stale_notice = 0.0


def available() -> bool:
    return BACKUP_DIR.is_dir()


def _read_status() -> dict:
    try:
        lines = (BACKUP_DIR / ".status").read_text(encoding="utf-8").splitlines()
    except OSError:
        return {}
    return dict(line.split("=", 1) for line in lines if "=" in line)


def status() -> dict:
    files = sorted(BACKUP_DIR.glob("proxsecure-*.dump"), key=lambda p: p.stat().st_mtime, reverse=True) if available() else []
    items = [
        {"name": p.name, "size": p.stat().st_size,
         "created": datetime.fromtimestamp(p.stat().st_mtime, tz=timezone.utc).isoformat()}
        for p in files
    ]
    last = files[0].stat().st_mtime if files else None
    age_hours = (time.time() - last) / 3600 if last else None
    return {
        "available": available(),
        "backups": items,
        "total_size": sum(i["size"] for i in items),
        "last_age_hours": round(age_hours, 1) if age_hours is not None else None,
        "stale": age_hours is None or age_hours > 2 * settings.backup_interval_hours,
        "pending_request": (BACKUP_DIR / ".request").exists() if available() else False,
        "last_attempt": _read_status(),
    }


def request_now() -> None:
    (BACKUP_DIR / ".request").write_text(datetime.now(timezone.utc).isoformat(), encoding="utf-8")


async def check_stale() -> None:
    """Si el ultimo respaldo tiene mas del doble del intervalo, avisa por los
    canales de notificacion (una vez al dia como maximo)."""
    global _last_stale_notice
    if not available():
        return
    st = status()
    if not st["stale"] or time.monotonic() - _last_stale_notice < STALE_NOTIFY_EVERY_SECONDS and _last_stale_notice:
        return
    _last_stale_notice = time.monotonic()
    detail = st["last_attempt"].get("message") if st["last_attempt"].get("result") == "error" else ""
    age = f"hace {st['last_age_hours']:.0f} horas" if st["last_age_hours"] is not None else "nunca"
    logger.warning("Respaldos atrasados: ultimo %s %s", age, detail)
    if notify.channels():
        await notify.send(
            "Prox Secure · respaldos atrasados",
            f"El ultimo respaldo de la base fue {age} (intervalo configurado: {settings.backup_interval_hours} h)."
            + (f"\nUltimo error: {detail}" if detail else "")
            + "\nRevisa: docker compose logs backup",
            "critical",
        )
