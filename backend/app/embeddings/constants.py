# Local Embedding Constants
# -------------------------
# Centralized bounds and defaults for the local embedding layer.

DEFAULT_LOCAL_EMBEDDING_MODEL: str = "sentence-transformers/all-MiniLM-L6-v2"
DEFAULT_LOCAL_EMBEDDING_DEVICE: str = "cpu"

# Maximum number of texts in a single embed_documents batch.
MAX_LOCAL_EMBEDDING_BATCH_SIZE: int = 64

# Maximum character length for any single input text.
# Texts beyond this are rejected to prevent excessive memory usage.
MAX_LOCAL_EMBEDDING_TEXT_CHARS: int = 10_000
