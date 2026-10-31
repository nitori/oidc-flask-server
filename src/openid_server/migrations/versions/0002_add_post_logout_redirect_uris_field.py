"""Add post_logout_redirect_uris field

Revision ID: 271dd553e57e
Revises: ca4d1efb09ef
Create Date: 2026-03-07 22:05:21.649111

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "271dd553e57e"
down_revision: Union[str, Sequence[str], None] = "ca4d1efb09ef"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        "client",
        sa.Column(
            "post_logout_redirect_uris", sa.JSON(), server_default="[]", nullable=False
        ),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("client", "post_logout_redirect_uris")
