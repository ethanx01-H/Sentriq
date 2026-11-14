"""Make the audit trail append-only at the database level.

Revision ID: 0011_audit_append_only
Revises: 0010_session_epoch
Create Date: 2026-11-14

A trail that the application can rewrite is not evidence. A trigger refuses
UPDATE, DELETE and TRUNCATE on fastapi_audit_logs for every role, including the
one the application connects as. The DDL is imported from the application module
so there is one definition, and the test harness installs the same one.
"""

from alembic import op

from sentriq.services.audit_guard import APPEND_ONLY_SQL, DROP_SQL

revision = "0011_audit_append_only"
down_revision = "0010_session_epoch"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(APPEND_ONLY_SQL)


def downgrade() -> None:
    op.execute(DROP_SQL)
