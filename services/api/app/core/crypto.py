"""Encryption of small secrets at rest (authenticator-app seeds)."""

import base64
from functools import lru_cache

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.core.config import get_settings


@lru_cache
def _fernet() -> Fernet:
    # A dedicated key derived from the application secret, so the same secret is
    # never used directly for two purposes.
    key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=b"sentinel-secrets-at-rest"
    ).derive(get_settings().secret_key.encode())
    return Fernet(base64.urlsafe_b64encode(key))


def encrypt(value: str) -> str:
    return _fernet().encrypt(value.encode()).decode()


def decrypt(value: str) -> str | None:
    try:
        return _fernet().decrypt(value.encode()).decode()
    except InvalidToken:
        return None
