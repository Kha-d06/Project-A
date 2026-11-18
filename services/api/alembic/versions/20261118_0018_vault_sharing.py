"""vault sharing and emergency access

Revision ID: 0018
Revises: 0017
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0018"
down_revision: str | None = "0017"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "sharing_keys",
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("public_key", sa.String(length=500), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_sharing_keys_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("user_id", name=op.f("pk_sharing_keys")),
    )
    op.create_table(
        "vault_shares",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("sender_id", sa.Uuid(), nullable=False),
        sa.Column("recipient_id", sa.Uuid(), nullable=False),
        sa.Column("ciphertext", sa.Text(), nullable=False),
        sa.Column("sender_ephemeral", sa.String(length=500), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["sender_id"],
            ["users.id"],
            name=op.f("fk_vault_shares_sender_id_users"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["recipient_id"],
            ["users.id"],
            name=op.f("fk_vault_shares_recipient_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_vault_shares")),
    )
    op.create_index(op.f("ix_vault_shares_sender_id"), "vault_shares", ["sender_id"], unique=False)
    op.create_index(
        op.f("ix_vault_shares_recipient_id"), "vault_shares", ["recipient_id"], unique=False
    )
    op.create_table(
        "emergency_contacts",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("grantor_id", sa.Uuid(), nullable=False),
        sa.Column("grantee_id", sa.Uuid(), nullable=False),
        sa.Column("wait_hours", sa.Integer(), nullable=False),
        sa.Column("state", sa.String(length=12), nullable=False),
        sa.Column("wrapped_vault_key", sa.Text(), nullable=False),
        sa.Column("sender_ephemeral", sa.String(length=500), nullable=False),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "state in ('invited', 'active', 'requested', 'denied')",
            name=op.f("ck_emergency_contacts_emergency_state_valid"),
        ),
        sa.ForeignKeyConstraint(
            ["grantor_id"],
            ["users.id"],
            name=op.f("fk_emergency_contacts_grantor_id_users"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["grantee_id"],
            ["users.id"],
            name=op.f("fk_emergency_contacts_grantee_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_emergency_contacts")),
        sa.UniqueConstraint("grantor_id", "grantee_id", name="uq_emergency_pair"),
    )
    op.create_index(
        op.f("ix_emergency_contacts_grantor_id"), "emergency_contacts", ["grantor_id"], unique=False
    )
    op.create_index(
        op.f("ix_emergency_contacts_grantee_id"), "emergency_contacts", ["grantee_id"], unique=False
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_emergency_contacts_grantee_id"), table_name="emergency_contacts")
    op.drop_index(op.f("ix_emergency_contacts_grantor_id"), table_name="emergency_contacts")
    op.drop_table("emergency_contacts")
    op.drop_index(op.f("ix_vault_shares_recipient_id"), table_name="vault_shares")
    op.drop_index(op.f("ix_vault_shares_sender_id"), table_name="vault_shares")
    op.drop_table("vault_shares")
    op.drop_table("sharing_keys")
