from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "postgresql+asyncpg://proxsecure:proxsecure@localhost:5432/proxsecure"

    ollama_host: str = "http://localhost:11434"
    ollama_model: str = "llama3.1:8b"

    anthropic_api_key: str | None = None
    ai_backend: str = "ollama"  # "ollama" o "claude"
    claude_model: str = "claude-sonnet-5-5"

    admin_api_key: str = "change-me-admin-key"

    alert_eval_interval_seconds: int = 30


settings = Settings()
