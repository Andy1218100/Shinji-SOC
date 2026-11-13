"""Nucleo de autenticacion: hashing de contrasenas (argon2id), TOTP (MFA)
y tokens firmados (cookies de sesion y tokens de login en dos pasos).
Ningun secreto se guarda en texto plano; las contrasenas temporales que
genera el sistema se muestran una sola vez al admin que crea la cuenta.
"""

import secrets

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from app.core.config import settings

_hasher = PasswordHasher()

SESSION_COOKIE = "proxsecure_session"
PENDING_COOKIE_MAX_AGE = 600  # 10 minutos para completar login/MFA/setup


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except VerifyMismatchError:
        return False
    except Exception:
        return False


def generate_temp_password() -> str:
    """Contrasena temporal legible, para que el admin la pueda dictar o
    copiar una sola vez. El usuario la cambia en su primer login."""
    return secrets.token_urlsafe(9)


def generate_mfa_secret() -> str:
    return pyotp.random_base32()


def totp_uri(username: str, secret: str) -> str:
    return pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="Prox Secure")


def verify_totp(secret: str, code: str) -> bool:
    return pyotp.TOTP(secret).verify(code, valid_window=1)


def _serializer(salt: str) -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(settings.session_secret_key, salt=salt)


def issue_session_token(user_id: str, role: str) -> str:
    return _serializer("session").dumps({"user_id": user_id, "role": role})


def read_session_token(token: str) -> dict | None:
    try:
        return _serializer("session").loads(token, max_age=settings.session_max_age_seconds)
    except (BadSignature, SignatureExpired):
        return None


def issue_pending_token(user_id: str, stage: str) -> str:
    """stage: 'setup' (primer login, falta password+MFA) o 'mfa' (falta codigo)."""
    return _serializer("pending-auth").dumps({"user_id": user_id, "stage": stage})


def read_pending_token(token: str, expected_stage: str) -> str | None:
    try:
        data = _serializer("pending-auth").loads(token, max_age=PENDING_COOKIE_MAX_AGE)
    except (BadSignature, SignatureExpired):
        return None
    if data.get("stage") != expected_stage:
        return None
    return data.get("user_id")
