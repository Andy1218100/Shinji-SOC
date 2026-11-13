from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "postgresql+asyncpg://proxsecure:proxsecure@localhost:5432/proxsecure"

    ollama_host: str = "http://localhost:11434"
    ollama_model: str = "qwen2.5:3b"

    anthropic_api_key: str | None = None
    ai_backend: str = "ollama"  # "ollama" o "claude"
    claude_model: str = "claude-sonnet-5-5"

    admin_api_key: str = "change-me-admin-key"

    alert_eval_interval_seconds: int = 30

    # GeoIP (MaxMind GeoLite2-City). Si el archivo no existe, el mapa de
    # ataques simplemente no tendra coordenadas hasta que se descargue.
    geoip_db_path: str = "data/GeoLite2-City.mmdb"
    maxmind_license_key: str | None = None

    # Motor IDS (heuristico, no es un modelo de ML entrenado)
    ids_window_seconds: int = 60
    ids_requests_threshold: int = 50  # requests de una misma IP en la ventana -> flood/fuerza bruta
    ids_404_threshold: int = 15  # 404s de una misma IP en la ventana -> escaneo


settings = Settings()
