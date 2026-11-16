import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.api.deps import require_superadmin
from app.models.user import User
from app.services import app_settings, auth, notify

router = APIRouter(prefix="/api/v1/config", tags=["config"])
logger = logging.getLogger("config")


class ConfigUpdate(BaseModel):
    mfa_code: str = Field(min_length=6, max_length=8)
    values: dict[str, str | int | bool | None] = Field(default_factory=dict)


class MfaOnly(BaseModel):
    mfa_code: str = Field(min_length=6, max_length=8)


def _check_mfa(admin: User, code: str) -> None:
    if not auth.verify_totp(admin.mfa_secret, code):
        raise HTTPException(status_code=401, detail="Codigo MFA invalido")


def _check_env_file() -> None:
    if not app_settings.env_file_available():
        raise HTTPException(
            status_code=409,
            detail=f"El servidor no puede escribir {app_settings.ENV_FILE}: falta montar el .env en docker-compose.yml",
        )


@router.get("", dependencies=[Depends(require_superadmin)])
async def get_config():
    return app_settings.public_view()


@router.put("")
async def put_config(payload: ConfigUpdate, admin: User = Depends(require_superadmin)):
    _check_mfa(admin, payload.mfa_code)
    _check_env_file()
    try:
        changed = app_settings.update(payload.values)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    # Sin valores en el log: puede haber secretos.
    logger.info("Configuracion cambiada por %s: %s", admin.username, ", ".join(changed) or "(nada)")
    return {"changed": changed, "config": app_settings.public_view()}


@router.post("/generate/{key}")
async def generate_secret(key: str, payload: MfaOnly, admin: User = Depends(require_superadmin)):
    _check_mfa(admin, payload.mfa_code)
    _check_env_file()
    try:
        app_settings.generate(key)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    logger.info("%s regenerado por %s", key, admin.username)
    return {"status": "ok", "logged_out": key == "SESSION_SECRET_KEY"}


@router.get("/ollama-models", dependencies=[Depends(require_superadmin)])
async def get_ollama_models():
    try:
        return {"models": await app_settings.ollama_models()}
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"No se pudo consultar Ollama: {exc}") from None


@router.post("/geoip-download", dependencies=[Depends(require_superadmin)])
async def geoip_download():
    try:
        await app_settings.download_geoip()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Fallo la descarga de MaxMind: {exc}") from None
    return {"status": "ok"}


@router.post("/notify-test", dependencies=[Depends(require_superadmin)])
async def notify_test():
    if not notify.channels():
        raise HTTPException(status_code=422, detail="No hay ningun canal configurado: guarda primero Telegram, ntfy o correo")
    results = await notify.send(
        "Prox Secure · prueba de notificacion",
        "Si lees esto, los avisos de Prox Secure llegan por este canal.",
        "warning",
    )
    return {"results": results}
