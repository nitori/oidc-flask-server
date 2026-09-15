"""Add ssh_public_key table

Revision ID: 8f3c2a1d9b7e
Revises: 271dd553e57e
Create Date: 2026-09-15 12:00:00.000000

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "8f3c2a1d9b7e"
down_revision: Union[str, Sequence[str], None] = "271dd553e57e"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "ssh_public_key",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("title", sa.String(), nullable=False),
        sa.Column("key_type", sa.String(), nullable=False),
        sa.Column("key_b64", sa.String(), nullable=False),
        sa.Column("fingerprint", sa.String(), nullable=False),
        sa.Column("created", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id", "key_b64"),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table("ssh_public_key")
