import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

MIN_PASSWORD_LENGTH = 10
MAX_PASSWORD_LENGTH = 128


def _validate_new_password(password: str) -> str:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Use at least {MIN_PASSWORD_LENGTH} characters for your password.")
    if len(set(password)) < 4:  # noqa: PLR2004 - rejects "aaaaaaaaaa"-style passwords
        raise ValueError("That password is too easy to guess.")
    return password


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(max_length=MAX_PASSWORD_LENGTH)
    display_name: str | None = Field(default=None, max_length=80)

    _check_password = field_validator("password")(_validate_new_password)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(max_length=MAX_PASSWORD_LENGTH)


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: str
    display_name: str | None
    role: str
    created_at: datetime
    email_verified_at: datetime | None = None


class SessionOut(BaseModel):
    user: UserOut
    csrf_token: str


class SessionStatus(BaseModel):
    """Answer to "who am I?". Being signed out is a normal state, not an error."""

    user: UserOut | None
    csrf_token: str | None


class SettingsOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    save_scan_history: bool
    sync_extension_events: bool


class ProfileOut(BaseModel):
    user: UserOut
    settings: SettingsOut


class SettingsUpdate(BaseModel):
    display_name: str | None = Field(default=None, max_length=80)
    save_scan_history: bool | None = None
    sync_extension_events: bool | None = None


class PasswordChange(BaseModel):
    current_password: str = Field(max_length=MAX_PASSWORD_LENGTH)
    new_password: str = Field(max_length=MAX_PASSWORD_LENGTH)

    _check_password = field_validator("new_password")(_validate_new_password)


class AccountDeletion(BaseModel):
    password: str = Field(max_length=MAX_PASSWORD_LENGTH)


class ActivityOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    action: str
    created_at: datetime


class ApiKeyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=80)


class ApiKeyOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    prefix: str
    created_at: datetime
    last_used_at: datetime | None


class ApiKeyCreated(ApiKeyOut):
    # Shown once. Only a digest is stored.
    key: str
