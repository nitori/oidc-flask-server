"""Add user permissions

Adds the user.permissions field. Creating apps now requires the
"create_apps" permission, so it is granted to all existing users that
already own at least one app.

Revision ID: 62e13fb4bf06
Revises: 5b9e4c7a2d1f
Create Date: 2026-10-31 12:00:00.000000

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "62e13fb4bf06"
down_revision: Union[str, Sequence[str], None] = "5b9e4c7a2d1f"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        "user",
        sa.Column("permissions", sa.JSON(), server_default="[]", nullable=False),
    )

    user = sa.table(
        "user",
        sa.column("id", sa.Uuid),
        sa.column("permissions", sa.JSON),
    )
    client = sa.table(
        "client",
        sa.column("user_id", sa.Uuid),
    )
    conn = op.get_bind()
    conn.execute(
        user.update()
        .where(user.c.id.in_(sa.select(client.c.user_id)))
        .values(permissions=["create_apps"])
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("user", "permissions")
