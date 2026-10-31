"""Hash client secrets

Renames client.client_secret to client.hashed_client_secret and replaces the
clear text secrets with their hashes. Existing clients keep working with the
same secret, but it can no longer be displayed.

Downgrading only renames the column back. The hashes cannot be reversed, so
confidential clients need a new secret afterward.

Revision ID: 5b9e4c7a2d1f
Revises: 8f3c2a1d9b7e
Create Date: 2026-10-12 12:00:00.000000

"""

import hashlib
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "5b9e4c7a2d1f"
down_revision: Union[str, Sequence[str], None] = "8f3c2a1d9b7e"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# same as openid_server.security.hash_client_secret, inlined so this migration
# keeps working should the application code change.
HASH_PREFIX = "sha256$"


def hash_client_secret(secret: str) -> str:
    return HASH_PREFIX + hashlib.sha256(secret.encode("utf-8")).hexdigest()


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table("client") as batch_op:
        batch_op.alter_column("client_secret", new_column_name="hashed_client_secret")

    client = sa.table(
        "client",
        sa.column("client_id", sa.String),
        sa.column("hashed_client_secret", sa.String),
    )
    conn = op.get_bind()
    rows = conn.execute(
        sa.select(client.c.client_id, client.c.hashed_client_secret)
    ).all()
    for client_id, secret in rows:
        if secret.startswith(HASH_PREFIX):
            continue
        conn.execute(
            client.update()
            .where(client.c.client_id == client_id)
            .values(hashed_client_secret=hash_client_secret(secret))
        )


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table("client") as batch_op:
        batch_op.alter_column("hashed_client_secret", new_column_name="client_secret")
