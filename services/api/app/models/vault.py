"""Password vaults. The server stores only ciphertext: the vault key is wrapped
with a key derived in the browser from a master password the server never sees."""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, utcnow


class Vault(Base):
    __tablename__ = "vaults"

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    # Key-derivation settings the browser needs to unlock: {"name", "iterations", "salt"}.
    kdf: Mapped[dict[str, Any]] = mapped_column()
    # The random vault key, encrypted with the master-password key (base64 of iv + ciphertext).
    wrapped_key: Mapped[str] = mapped_column(String(200))
    # The vault contents, encrypted with the vault key (base64 of iv + ciphertext).
    data: Mapped[str] = mapped_column(Text)
    # Increases with every save; a save based on an older version is refused.
    version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(default=utcnow)
