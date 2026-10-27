"""users.removed_at

Marks accounts removed by an administrator. Removed accounts keep their row so the
append-only audit trail and incident history still resolve, but they cannot sign in
and are hidden from user lists. Additive and nullable: safe to apply while the
previous release is still running.

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-27 19:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("users", sa.Column("removed_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("users", "removed_at")
