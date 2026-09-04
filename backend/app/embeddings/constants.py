# Local Embedding Constants
# -------------------------
# Centralized bounds and defaults for the local embedding layer.

DEFAULT_LOCAL_EMBEDDING_MODEL: str = "sentence-transformers/all-MiniLM-L6-v2"
DEFAULT_LOCAL_EMBEDDING_DEVICE: str = "cpu"
LOCAL_EMBEDDING_PREPROCESSING_VERSION: str = "st-role-window-v1"

# Maximum number of texts in a single embed_documents batch.
MAX_LOCAL_EMBEDDING_BATCH_SIZE: int = 64

# Coarse memory bound. The service separately checks the loaded tokenizer's
# exact, untruncated token count against the model sequence window.
MAX_LOCAL_EMBEDDING_TEXT_CHARS: int = 10_000
