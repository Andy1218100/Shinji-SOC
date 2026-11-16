from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "postgresql+asyncpg://proxsecure:proxsecure@localhost:5432/proxsecure"

    ollama_host: str = "http://localhost:11434"
    ollama_model: str = "qwen2.5:3b"

    anthropic_api_key: str | None = None
    ai_backend: str = "ollama"  # "ollama" o "claude"
    claude_model: str = "claude-sonnet-5-5"

    # Firma las cookies de sesion (itsdangerous). Cambiala en produccion;
    # cambiarla invalida todas las sesiones activas (fuerza a volver a
    # loguearse, no es destructivo).
    session_secret_key: str = "change-me-session-secret"
    session_max_age_seconds: int = 60 * 60 * 24  # 24h
    # Cookies "Secure" (solo se mandan por HTTPS). Dejalo en false para
    # desarrollo local por HTTP; activalo en produccion detras de HTTPS.
    session_cookie_secure: bool = False

    login_max_attempts: int = 5
    login_lockout_seconds: int = 300

    alert_eval_interval_seconds: int = 30

    # GeoIP (MaxMind GeoLite2-City). Si el archivo no existe, el mapa de
    # ataques simplemente no tendra coordenadas hasta que se descargue.
    geoip_db_path: str = "data/GeoLite2-City.mmdb"
    maxmind_license_key: str | None = None
    maxmind_account_id: str | None = None

    # Motor IDS (heuristico, no es un modelo de ML entrenado)
    ids_window_seconds: int = 60
    ids_requests_threshold: int = 50  # requests de una misma IP en la ventana -> flood/fuerza bruta
    ids_404_threshold: int = 15  # 404s de una misma IP en la ventana -> escaneo
    # Logins fallidos (SSH o web de Proxmox) de una misma IP en la ventana
    ssh_window_seconds: int = 600
    ssh_fail_threshold: int = 5

    # Escaneo de vulnerabilidades (OSV.dev) sobre el inventario de paquetes
    # que reporta el agente. Una vez al dia por defecto.
    vuln_scan_interval_seconds: int = 86400

    # Notificaciones (services/notify.py). Un canal sin datos no se usa.
    notify_min_severity: str = "critical"  # warning | critical
    notify_include_ips: bool = False
    notify_cooldown_seconds: int = 600
    notify_vulns: bool = True
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""
    ntfy_url: str = ""
    ntfy_token: str = ""
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    smtp_to: str = ""
    smtp_starttls: bool = True

    # Respaldos (los hace el contenedor "backup"; ver scripts/backup_loop.sh)
    backup_interval_hours: int = 24
    backup_keep: int = 14

    # Token del auditor externo (servidor MCP en la PC del admin, ver
    # tools/mcp_audit). Vacio = los endpoints /api/v1/audit/* quedan apagados.
    audit_api_token: str = ""


settings = Settings()
