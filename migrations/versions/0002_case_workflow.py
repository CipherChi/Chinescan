"""Mark the backwards-compatible case payload workflow revision.

Case notes, links, and activity are stored in the existing generic JSON payload column,
so this revision intentionally changes no physical SQLite tables and rewrites no records.
Older Case payloads remain readable through defaults on the Case model.
"""

revision = "0002_case_workflow"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Record the application-level payload evolution without changing stored data."""


def downgrade() -> None:
    """No physical changes to reverse; data-bearing payloads are never downgraded."""
