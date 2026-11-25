"""Disposable email aliases

Revision ID: 0022
Revises: 0021
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0022"
down_revision: str | None = "0021"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "email_aliases",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("local_part", sa.String(length=64), nullable=False),
        sa.Column("domain", sa.String(length=253), nullable=False),
        sa.Column("label", sa.String(length=120), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("paused_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("forwarded_count", sa.Integer(), nullable=False),
        sa.Column("blocked_count", sa.Integer(), nullable=False),
        sa.Column("last_forwarded_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("local_part", "domain", name="uq_email_alias_address"),
    )
    op.create_index("ix_email_aliases_user_id", "email_aliases", ["user_id"])


def downgrade() -> None:
    op.drop_index("ix_email_aliases_user_id", table_name="email_aliases")
    op.drop_table("email_aliases")
