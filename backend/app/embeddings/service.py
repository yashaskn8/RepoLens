"""Local Embedding Service using Sentence Transformers.

Provides thread-safe, lazy-loaded local embedding inference on CPU.
The model is loaded exactly once on first use and reused for all
subsequent calls. All methods perform strict input validation and
output verification (finite values, correct dimensions, normalization).
"""

from __future__ import annotations

import logging
import math
import re
import threading
from typing import TYPE_CHECKING

from app.embeddings.constants import (
    DEFAULT_LOCAL_EMBEDDING_DEVICE,
    DEFAULT_LOCAL_EMBEDDING_MODEL,
    MAX_LOCAL_EMBEDDING_BATCH_SIZE,
    MAX_LOCAL_EMBEDDING_TEXT_CHARS,
)

if TYPE_CHECKING:
    from sentence_transformers import SentenceTransformer

logger = logging.getLogger(__name__)

# Pattern to detect local filesystem paths in error messages
_PATH_PATTERN = re.compile(r"[A-Za-z]:\\[^\s\"']+|/(?:home|Users|tmp|var|root)/[^\s\"']+")


class LocalEmbeddingError(Exception):
    """Raised when local embedding inference fails."""


class LocalEmbeddingService:
    """Thread-safe local embedding service backed by Sentence Transformers.

    The underlying ``SentenceTransformer`` model is loaded lazily on first
    use and cached for the lifetime of this instance.  All public methods
    validate inputs and outputs strictly — empty inputs, oversized texts,
    NaN/Inf vectors, and dimension mismatches are rejected with clear errors.
    """

    def __init__(
        self,
        model_name: str = DEFAULT_LOCAL_EMBEDDING_MODEL,
        device: str = DEFAULT_LOCAL_EMBEDDING_DEVICE,
    ) -> None:
        self.model_name = model_name
        self.device = device
        self._model: SentenceTransformer | None = None
        self._lock = threading.Lock()
        self._dimensions: int | None = None
        self._max_seq_length: int | None = None

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def dimensions(self) -> int:
        """Return the embedding dimension, loading the model if needed."""
        self._ensure_loaded()
        assert self._dimensions is not None
        return self._dimensions

    @property
    def max_seq_length(self) -> int:
        """Return the model's maximum sequence length in tokens."""
        self._ensure_loaded()
        assert self._max_seq_length is not None
        return self._max_seq_length

    @property
    def is_loaded(self) -> bool:
        """Return True if the model has been loaded."""
        return self._model is not None

    # ------------------------------------------------------------------
    # Public embedding methods
    # ------------------------------------------------------------------

    def embed_text(self, text: str) -> list[float]:
        """Embed a single text string and return its vector.

        Args:
            text: A non-empty string to embed.

        Returns:
            A list of floats representing the embedding vector.

        Raises:
            LocalEmbeddingError: If the input is invalid or inference fails.
        """
        self._validate_single_text(text)
        self._ensure_loaded()
        return self._encode_single(text)

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        """Embed a batch of document texts.

        Args:
            texts: A non-empty list of non-empty strings (max batch size
                   ``MAX_LOCAL_EMBEDDING_BATCH_SIZE``).

        Returns:
            A list of embedding vectors, one per input text.

        Raises:
            LocalEmbeddingError: If any input is invalid or inference fails.
        """
        self._validate_batch(texts)
        self._ensure_loaded()
        return self._encode_batch(texts)

    def embed_query(self, query: str) -> list[float]:
        """Embed a query string.

        Functionally identical to ``embed_text`` but kept separate for
        semantic clarity and to allow future query-specific prompting.

        Args:
            query: A non-empty query string.

        Returns:
            A list of floats representing the query embedding.

        Raises:
            LocalEmbeddingError: If the input is invalid or inference fails.
        """
        self._validate_single_text(query)
        self._ensure_loaded()
        return self._encode_single(query)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _ensure_loaded(self) -> None:
        """Load the model exactly once (thread-safe)."""
        if self._model is not None:
            return
        with self._lock:
            # Double-checked locking
            if self._model is not None:
                return
            try:
                from sentence_transformers import SentenceTransformer

                model = SentenceTransformer(self.model_name, device=self.device)
                if hasattr(model, "get_embedding_dimension"):
                    dim = model.get_embedding_dimension()
                else:
                    dim = model.get_sentence_embedding_dimension()
                if not isinstance(dim, int) or dim <= 0:
                    raise LocalEmbeddingError(
                        f"Model returned invalid embedding dimension: {dim}"
                    )
                self._dimensions = dim
                self._max_seq_length = getattr(model, "max_seq_length", 256)
                self._model = model
                logger.info(
                    "Loaded local embedding model %s (dim=%d, max_seq=%d, device=%s)",
                    self.model_name,
                    self._dimensions,
                    self._max_seq_length,
                    self.device,
                )
            except LocalEmbeddingError:
                raise
            except Exception as exc:
                raise LocalEmbeddingError(
                    f"Failed to load embedding model: {_sanitize_error(exc)}"
                ) from None

    def _encode_single(self, text: str) -> list[float]:
        """Encode a single text and validate the resulting vector."""
        assert self._model is not None
        try:
            result = self._model.encode(
                text,
                normalize_embeddings=True,
                convert_to_numpy=True,
            )
            vec = result.tolist()
        except Exception as exc:
            raise LocalEmbeddingError(
                f"Encoding failed: {_sanitize_error(exc)}"
            ) from None
        self._validate_vector(vec)
        return vec

    def _encode_batch(self, texts: list[str]) -> list[list[float]]:
        """Encode a batch of texts and validate all resulting vectors."""
        assert self._model is not None
        try:
            results = self._model.encode(
                texts,
                batch_size=min(len(texts), 32),
                normalize_embeddings=True,
                convert_to_numpy=True,
            )
            vectors = results.tolist()
        except Exception as exc:
            raise LocalEmbeddingError(
                f"Batch encoding failed: {_sanitize_error(exc)}"
            ) from None

        if len(vectors) != len(texts):
            raise LocalEmbeddingError(
                f"Expected {len(texts)} vectors, got {len(vectors)}"
            )
        for vec in vectors:
            self._validate_vector(vec)
        return vectors

    def _validate_single_text(self, text: str) -> None:
        """Validate a single input text."""
        if not isinstance(text, str):
            raise LocalEmbeddingError(
                f"Expected str, got {type(text).__name__}"
            )
        if not text.strip():
            raise LocalEmbeddingError("Input text must not be empty or whitespace-only")
        if len(text) > MAX_LOCAL_EMBEDDING_TEXT_CHARS:
            raise LocalEmbeddingError(
                f"Input text exceeds maximum length of {MAX_LOCAL_EMBEDDING_TEXT_CHARS} characters"
            )

    def _validate_batch(self, texts: list[str]) -> None:
        """Validate a batch of input texts."""
        if not isinstance(texts, list):
            raise LocalEmbeddingError(
                f"Expected list, got {type(texts).__name__}"
            )
        if len(texts) == 0:
            raise LocalEmbeddingError("Document list must not be empty")
        if len(texts) > MAX_LOCAL_EMBEDDING_BATCH_SIZE:
            raise LocalEmbeddingError(
                f"Batch size {len(texts)} exceeds maximum of {MAX_LOCAL_EMBEDDING_BATCH_SIZE}"
            )
        for i, text in enumerate(texts):
            try:
                self._validate_single_text(text)
            except LocalEmbeddingError as exc:
                raise LocalEmbeddingError(
                    f"Invalid text at index {i}: {exc}"
                ) from None

    def _validate_vector(self, vec: list[float]) -> None:
        """Validate that a vector has correct dimension and finite values."""
        if len(vec) != self._dimensions:
            raise LocalEmbeddingError(
                f"Expected dimension {self._dimensions}, got {len(vec)}"
            )
        for i, val in enumerate(vec):
            if not math.isfinite(val):
                raise LocalEmbeddingError(
                    f"Non-finite value at index {i}: {val}"
                )
        # Verify vector is not all zeros (would indicate failed normalization)
        norm_sq = sum(v * v for v in vec)
        if norm_sq < 1e-12:
            raise LocalEmbeddingError(
                "Embedding vector is effectively zero — model output invalid"
            )


def _sanitize_error(exc: Exception) -> str:
    """Strip local filesystem paths from exception messages."""
    msg = str(exc)
    return _PATH_PATTERN.sub("<redacted-path>", msg)
