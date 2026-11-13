"""Agente recolector de metricas para Prox Secure.

Recolecta CPU, memoria, disco, carga y red del host donde corre y las
envia periodicamente al servidor central via HTTP.
"""

import logging
import os
import sys
import time
from datetime import datetime, timezone

import httpx
import psutil
import yaml

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("collector")

CONFIG_PATH = os.environ.get("PROX_SECURE_CONFIG", os.path.join(os.path.dirname(__file__), "config.yaml"))


def load_config() -> dict:
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
            config = yaml.safe_load(fh) or {}
    else:
        config = {}

    config.setdefault("server_url", os.environ.get("PROX_SECURE_SERVER_URL", "http://localhost:8000"))
    config.setdefault("api_key", os.environ.get("PROX_SECURE_API_KEY", ""))
    config.setdefault("interval_seconds", int(os.environ.get("PROX_SECURE_INTERVAL", "15")))

    if not config["api_key"]:
        logger.error("Falta api_key. Define config.yaml o PROX_SECURE_API_KEY.")
        sys.exit(1)

    return config


def collect() -> dict:
    disk = psutil.disk_usage("/")
    mem = psutil.virtual_memory()
    net = psutil.net_io_counters()
    try:
        load1, load5, load15 = os.getloadavg()
    except (AttributeError, OSError):
        load1, load5, load15 = (None, None, None)

    return {
        "ts": datetime.now(timezone.utc).isoformat(),
        "cpu_percent": psutil.cpu_percent(interval=1),
        "mem_percent": mem.percent,
        "mem_used_mb": mem.used / (1024 * 1024),
        "mem_total_mb": mem.total / (1024 * 1024),
        "disk_percent": disk.percent,
        "disk_used_gb": disk.used / (1024 ** 3),
        "disk_total_gb": disk.total / (1024 ** 3),
        "load1": load1,
        "load5": load5,
        "load15": load15,
        "net_rx_bytes": net.bytes_recv,
        "net_tx_bytes": net.bytes_sent,
        "uptime_seconds": int(time.time() - psutil.boot_time()),
    }


def main() -> None:
    config = load_config()
    url = f"{config['server_url'].rstrip('/')}/api/v1/ingest"
    headers = {"X-API-Key": config["api_key"]}

    logger.info("Enviando metricas a %s cada %ss", url, config["interval_seconds"])

    with httpx.Client(timeout=10) as client:
        while True:
            try:
                payload = collect()
                resp = client.post(url, json=payload, headers=headers)
                resp.raise_for_status()
            except Exception:
                logger.exception("Fallo al enviar metricas")
            time.sleep(config["interval_seconds"])


if __name__ == "__main__":
    main()
