"""End-to-end encrypted password vault.

The browser derives a key from the master password (PBKDF2-SHA256), uses it to
wrap a random vault key, and encrypts the vault with that key (AES-256-GCM).
This API only stores and returns the ciphertext, so neither Qalaa nor
anyone with database access can read a vault. That also means a forgotten
master password cannot be recovered.
"""

import base64
import binascii
import re
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field, field_validator

from app.api.auth import record_event
from app.api.deps import Db, SessionUser
from app.core import rate_limit
from app.core.errors import ApiError
from app.core.rate_limit import RateLimit
from app.core.security import verify_password
from app.models import Vault
from app.models.base import utcnow

router = APIRouter(prefix="/vault", tags=["Password vault"])

READ_LIMIT = RateLimit("vault-read", max_requests=600, window_seconds=3600)
WRITE_LIMIT = RateLimit("vault-write", max_requests=300, window_seconds=3600)
DELETE_LIMIT = RateLimit("vault-delete", max_requests=10, window_seconds=3600)

MAX_DATA_CHARS = 4 * 1024 * 1024  # about 3 MB of ciphertext: tens of thousands of entries
MIN_ITERATIONS = 310_000
MAX_ITERATIONS = 10_000_000
_BASE64 = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")


def _decoded_length(value: str) -> int:
    if not _BASE64.fullmatch(value) or len(value) % 4:
        raise ValueError("must be base64")
    try:
        return len(base64.b64decode(value, validate=True))
    except binascii.Error as exc:
        raise ValueError("must be base64") from exc


class Kdf(BaseModel):
    name: Literal["PBKDF2-SHA256"]
    iterations: int = Field(ge=MIN_ITERATIONS, le=MAX_ITERATIONS)
    salt: str = Field(max_length=100)

    @field_validator("salt")
    @classmethod
    def salt_size(cls, value: str) -> str:
        if not 16 <= _decoded_length(value) <= 64:
            raise ValueError("salt must be 16 to 64 bytes")
        return value


class VaultIn(BaseModel):
    kdf: Kdf
    wrapped_key: str = Field(max_length=200)
    data: str = Field(max_length=MAX_DATA_CHARS)
    # The version this save is based on; null when creating the vault.
    expected_version: int | None = None

    @field_validator("wrapped_key")
    @classmethod
    def wrapped_key_size(cls, value: str) -> str:
        # 12-byte IV + 32-byte key + 16-byte tag
        if _decoded_length(value) != 60:
            raise ValueError("wrapped_key has the wrong size")
        return value

    @field_validator("data")
    @classmethod
    def data_size(cls, value: str) -> str:
        if _decoded_length(value) < 12 + 16:
            raise ValueError("data is too short to be ciphertext")
        return value


class VaultOut(BaseModel):
    kdf: dict[str, Any]
    wrapped_key: str
    data: str
    version: int
    updated_at: Any


class VaultSaved(BaseModel):
    version: int
    updated_at: Any


class VaultDelete(BaseModel):
    password: Annotated[str, Field(min_length=1, max_length=1024)]


@router.get("", response_model=VaultOut)
def get_vault(db: Db, user: SessionUser) -> VaultOut:
    rate_limit.enforce(READ_LIMIT, f"user:{user.id}")
    vault = db.get(Vault, user.id)
    if vault is None:
        raise ApiError(404, "vault_not_found", "You have not created a password vault yet.")
    return VaultOut(
        kdf=vault.kdf,
        wrapped_key=vault.wrapped_key,
        data=vault.data,
        version=vault.version,
        updated_at=vault.updated_at,
    )


@router.put("", response_model=VaultSaved)
def save_vault(body: VaultIn, request: Request, db: Db, user: SessionUser) -> VaultSaved:
    rate_limit.enforce(WRITE_LIMIT, f"user:{user.id}")
    # Lock the row so two tabs saving at once cannot both pass the version check.
    vault = db.get(Vault, user.id, with_for_update=True)
    if vault is None:
        if body.expected_version is not None:
            raise ApiError(409, "vault_conflict", "This vault was deleted on another device.")
        vault = Vault(
            user_id=user.id,
            kdf=body.kdf.model_dump(),
            wrapped_key=body.wrapped_key,
            data=body.data,
            version=1,
        )
        db.add(vault)
        record_event(db, request, user, "vault_created")
    else:
        if body.expected_version != vault.version:
            raise ApiError(
                409,
                "vault_conflict",
                "Your vault was changed on another device. Reload it, then make your change again.",
                details={"version": vault.version},
            )
        if body.kdf.model_dump() != vault.kdf or body.wrapped_key != vault.wrapped_key:
            record_event(db, request, user, "vault_master_password_changed")
        vault.kdf = body.kdf.model_dump()
        vault.wrapped_key = body.wrapped_key
        vault.data = body.data
        vault.version += 1
        vault.updated_at = utcnow()
    db.commit()
    return VaultSaved(version=vault.version, updated_at=vault.updated_at)


@router.post("/delete", status_code=204)
def delete_vault(body: VaultDelete, request: Request, db: Db, user: SessionUser) -> None:
    """Deleting needs the account password: a stolen session alone cannot wipe the vault."""
    rate_limit.enforce(DELETE_LIMIT, f"user:{user.id}")
    if not verify_password(body.password, user.password_hash):
        raise ApiError(403, "wrong_password", "That password is not correct.")
    vault = db.get(Vault, user.id)
    if vault is not None:
        db.delete(vault)
        record_event(db, request, user, "vault_deleted")
    db.commit()
