"""screenshot scans

Revision ID: 0008
Revises: 0007
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_OLD = "('url', 'message', 'file', 'qr', 'website', 'apk')"
_NEW = "('url', 'message', 'file', 'qr', 'website', 'apk', 'screenshot')"


def upgrade() -> None:
    with op.batch_alter_table("scan_jobs") as batch:
        batch.drop_constraint("scan_type_valid", type_="check")
        batch.create_check_constraint("scan_type_valid", f"scan_type IN {_NEW}")


def downgrade() -> None:
    op.execute("DELETE FROM scan_jobs WHERE scan_type = 'screenshot'")
    with op.batch_alter_table("scan_jobs") as batch:
        batch.drop_constraint("scan_type_valid", type_="check")
        batch.create_check_constraint("scan_type_valid", f"scan_type IN {_OLD}")
