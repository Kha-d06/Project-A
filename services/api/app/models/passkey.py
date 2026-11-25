"""Passkeys (WebAuthn credentials) for signing in to a Qalaa account.

Only the public key, the credential id and a signature counter are kept;
the private key never leaves the person's device. Challenges are random,
single-use, bound to one purpose (and to the user, for registration) and
expire after five minutes (OWASP Authentication Cheat Sheet, WebAuthn).
"""

import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, utcnow


class AccountPasskey(Base):
    __tablename__ = "account_passkeys"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    credential_id: Mapped[bytes] = mapped_column(LargeBinary(1024), unique=True)
    public_key: Mapped[bytes] = mapped_column(LargeBinary(2048))
    sign_count: Mapped[int] = mapped_column(default=0)
    # A short name the person chose, e.g. "Laptop" or "Phone".
    name: Mapped[str] = mapped_column(String(60))
    transports: Mapped[str | None] = mapped_column(String(120))
    # Synced passkeys (iCloud Keychain, Google Password Manager) report backed-up.
    backed_up: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    last_used_at: Mapped[datetime | None]


class WebAuthnChallenge(Base):
    __tablename__ = "webauthn_challenges"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    # Set for registration (the signed-in person); empty for sign-in, where the
    # passkey itself names the account.
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    challenge: Mapped[bytes] = mapped_column(LargeBinary(64))
    # "register" or "login".
    purpose: Mapped[str] = mapped_column(String(16))
    expires_at: Mapped[datetime]
    used_at: Mapped[datetime | None]
