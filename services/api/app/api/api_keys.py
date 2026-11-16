import uuid

from fastapi import APIRouter, Request
from sqlalchemy import func, select

from app.api.auth import record_event
from app.api.deps import API_KEY_PREFIX, Db, SessionUser
from app.core.errors import ApiError
from app.core.security import new_token, token_digest
from app.models import ApiKey
from app.models.base import utcnow
from app.schemas.auth import ApiKeyCreate, ApiKeyCreated, ApiKeyOut

router = APIRouter(prefix="/user/api-keys", tags=["API keys"])

MAX_ACTIVE_KEYS = 10
_PREFIX_SHOWN = 12


@router.post("", response_model=ApiKeyCreated, status_code=201)
def create_key(body: ApiKeyCreate, request: Request, user: SessionUser, db: Db) -> ApiKeyCreated:
    active = db.scalar(
        select(func.count())
        .select_from(ApiKey)
        .where(ApiKey.user_id == user.id, ApiKey.revoked_at.is_(None))
    )
    if (active or 0) >= MAX_ACTIVE_KEYS:
        raise ApiError(409, "too_many_keys", f"You can have up to {MAX_ACTIVE_KEYS} active keys.")
    secret = f"{API_KEY_PREFIX}{new_token()}"
    key = ApiKey(
        user_id=user.id,
        name=body.name.strip(),
        prefix=secret[:_PREFIX_SHOWN],
        key_digest=token_digest(secret),
    )
    db.add(key)
    record_event(db, request, user, "api_key_created", key.name)
    db.commit()
    return ApiKeyCreated(**ApiKeyOut.model_validate(key).model_dump(), key=secret)


@router.get("", response_model=list[ApiKeyOut])
def list_keys(user: SessionUser, db: Db) -> list[ApiKey]:
    return list(
        db.scalars(
            select(ApiKey)
            .where(ApiKey.user_id == user.id, ApiKey.revoked_at.is_(None))
            .order_by(ApiKey.created_at.desc())
        )
    )


@router.delete("/{key_id}", status_code=204)
def revoke_key(key_id: uuid.UUID, request: Request, user: SessionUser, db: Db) -> None:
    key = db.get(ApiKey, key_id)
    if key is None or key.user_id != user.id or key.revoked_at is not None:
        raise ApiError(404, "key_not_found", "This key does not exist.")
    key.revoked_at = utcnow()
    record_event(db, request, user, "api_key_revoked", key.name)
    db.commit()
