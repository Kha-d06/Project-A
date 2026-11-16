from pydantic import BaseModel, EmailStr, Field, field_validator

from app.schemas.auth import MAX_PASSWORD_LENGTH, _validate_new_password


class TokenRequest(BaseModel):
    token: str = Field(min_length=10, max_length=100)


class ResetRequest(BaseModel):
    email: EmailStr


class ResetConfirm(BaseModel):
    token: str = Field(min_length=10, max_length=100)
    new_password: str = Field(max_length=MAX_PASSWORD_LENGTH)

    _check_password = field_validator("new_password")(_validate_new_password)


class TwoFactorSetup(BaseModel):
    secret: str
    otpauth_uri: str
    # PNG of the QR code as a data: URL, rendered on the server so the secret is
    # never sent to a third-party QR service.
    qr_code: str


class CodeRequest(BaseModel):
    code: str = Field(min_length=6, max_length=20)


class TwoFactorEnabled(BaseModel):
    backup_codes: list[str]


class TwoFactorDisable(BaseModel):
    password: str = Field(max_length=MAX_PASSWORD_LENGTH)
    code: str = Field(min_length=6, max_length=20)


class LoginChallenge(BaseModel):
    two_factor_required: bool = True
    challenge: str


class ChallengeAnswer(BaseModel):
    challenge: str = Field(max_length=300)
    code: str = Field(min_length=6, max_length=20)
