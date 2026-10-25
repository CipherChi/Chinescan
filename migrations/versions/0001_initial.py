"""Create the generic versioned records table."""

import sqlalchemy as sa
from alembic import op

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "records",
        sa.Column("record_type", sa.String(80), primary_key=True),
        sa.Column("record_id", sa.String(255), primary_key=True),
        sa.Column("payload", sa.JSON(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("records")
