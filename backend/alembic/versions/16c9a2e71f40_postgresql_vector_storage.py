"""PostgreSQL pgvector storage managed by the migration lifecycle."""

import os

from alembic import op

revision = "16c9a2e71f40"
down_revision = "15e7d4a3b820"
branch_labels = None
depends_on = None


def upgrade():
    enabled = os.environ.get("ENABLE_PGVECTOR", "").strip().lower() in {"1", "true", "yes", "on"}
    if op.get_bind().dialect.name != "postgresql" or not enabled:
        return
    op.execute("CREATE EXTENSION IF NOT EXISTS vector")
    # Dimension is namespace-authoritative, allowing configured embedding
    # providers with different dimensions to coexist without implicit casts.
    op.execute("""
        CREATE TABLE IF NOT EXISTS code_embeddings (
            id VARCHAR(256) NOT NULL,
            namespace VARCHAR(128) NOT NULL,
            dimensions INTEGER NOT NULL CHECK (dimensions > 0 AND dimensions <= 16000),
            model_name VARCHAR(128) NOT NULL,
            index_version VARCHAR(32) NOT NULL,
            embedding vector NOT NULL,
            metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (namespace, id)
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS ix_code_embeddings_namespace ON code_embeddings (namespace)")


def downgrade():
    if op.get_bind().dialect.name == "postgresql":
        op.execute("DROP TABLE IF EXISTS code_embeddings")
