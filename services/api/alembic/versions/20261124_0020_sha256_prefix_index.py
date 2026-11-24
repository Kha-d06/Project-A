"""k-anonymous hash lookups: prefix index over SHA-256 indicators

Revision ID: 0020
Revises: 0019
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0020"
down_revision: str | None = "0019"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index(
        "ix_threat_indicators_sha256_prefix",
        "threat_indicators",
        ["value"],
        unique=False,
        postgresql_where=sa.text("kind = 'sha256'"),
        postgresql_ops={"value": "text_pattern_ops"},
    )


def downgrade() -> None:
    op.drop_index("ix_threat_indicators_sha256_prefix", table_name="threat_indicators")
