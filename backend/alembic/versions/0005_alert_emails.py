"""alert email notifications

users.alert_email_severity (NULL = off) holds each person's opt-in and minimum severity;
alerts.notified_at marks alerts already handled by the digest sender, and
organizations.alert_email_sent_at paces it. Existing alerts are marked as handled so
turning emails on never sends the backlog. Additive: safe to apply while the previous
release is still running.

Revision ID: 0005
Revises: 0004
Create Date: 2026-10-28 16:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("users", sa.Column("alert_email_severity", sa.String(length=16), nullable=True))
    op.create_check_constraint("ck_users_alert_email_severity", "users", "alert_email_severity IN ('critical', 'high', 'medium', 'low')")
    op.add_column("alerts", sa.Column("notified_at", sa.DateTime(timezone=True), nullable=True))
    op.execute("UPDATE alerts SET notified_at = now()")
    op.create_index("ix_alerts_pending_notification", "alerts", ["org_id"], unique=False, postgresql_where=sa.text("notified_at IS NULL"))
    op.add_column("organizations", sa.Column("alert_email_sent_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("organizations", "alert_email_sent_at")
    op.drop_index("ix_alerts_pending_notification", table_name="alerts")
    op.drop_column("alerts", "notified_at")
    op.drop_constraint("ck_users_alert_email_severity", "users", type_="check")
    op.drop_column("users", "alert_email_severity")
