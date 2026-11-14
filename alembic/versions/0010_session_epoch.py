"""Add a session epoch so a session can be revoked before it expires.

Revision ID: 0010_session_epoch
Revises: 0009_retention_sla_merge
Create Date: 2026-11-14

A signed cookie cannot be un-signed, so revocation needs a value the server can
change: the cookie carries the epoch it was issued with and any request whose
epoch is behind the row is refused. Bumped on sign-out, on an administrator
revoking sessions, and on any password or role change.
"""

import sqlalchemy as sa
from alembic import op

revision = "0010_session_epoch"
down_revision = "0009_retention_sla_merge"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "fastapi_users",
        sa.Column("session_epoch", sa.Integer(), nullable=False, server_default=sa.text("0")),
    )


def downgrade() -> None:
    op.drop_column("fastapi_users", "session_epoch")
