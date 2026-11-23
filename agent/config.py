import os
import sys

import yaml

CONFIG_PATH = os.environ.get(
    "SHINJI_SOC_CONFIG", os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.yaml")
)

_DEFAULTS = {
    "server_url": "http://localhost:8000",
    "api_key": "",
    "metrics_interval_seconds": 15,
    "log_paths": [],
    "process_watch": {"interval_seconds": 10, "service_users": []},
    "command_poll_interval_seconds": 10,
    "fail2ban_jail": "shinjisoc",
    "inventory_interval_seconds": 86400,
    "discovery_interval_seconds": 86400,
    "connections": {"enabled": True, "interval_seconds": 60},
}


def load() -> dict:
    config = dict(_DEFAULTS)

    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
            config.update(yaml.safe_load(fh) or {})

    config["server_url"] = os.environ.get("SHINJI_SOC_SERVER_URL", config["server_url"])
    config["api_key"] = os.environ.get("SHINJI_SOC_API_KEY", config["api_key"])

    if not config["api_key"]:
        print("Falta api_key. Define config.yaml o SHINJI_SOC_API_KEY.", file=sys.stderr)
        sys.exit(1)

    return config
