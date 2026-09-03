"""Async adapter bridging LocalEmbeddingService to EmbeddingProvider.

This module implements ``LocalEmbeddingAdapter``, a concrete subclass of
the canonical ``EmbeddingProvider`` interface that delegates all inference
to a ``LocalEmbeddingService`` instance running on CPU via
``asyncio.to_thread`` so as not to block the event loop.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

from app.core.config import get_settings
from app.embeddings.service import LocalEmbeddingService
from app.indexing.embeddings import EmbeddingProvider
from app.indexing.schemas import (
    EmbeddingRequest,
    EmbeddingResponse,
    EmbeddingResult,
)

logger = logging.getLogger(__name__)


class LocalEmbeddingAdapter(EmbeddingProvider):
    """Adapts :class:`LocalEmbeddingService` to the ``EmbeddingProvider`` ABC.

    Synchronous CPU-bound inference is dispatched via
    ``asyncio.to_thread`` to keep the async event loop responsive.
    """

    def __init__(self, service: Optional[LocalEmbeddingService] = None) -> None:
        if service is not None:
            self._service = service
        else:
            settings = get_settings()
            self._service = LocalEmbeddingService(
                model_name=settings.LOCAL_EMBEDDING_MODEL,
                device=settings.LOCAL_EMBEDDING_DEVICE,
            )

    @property
    def provider_name(self) -> str:  # noqa: D102
        return "local"

    @property
    def default_model(self) -> str:  # noqa: D102
        return self._service.model_name

    @property
    def dimensions(self) -> int:  # noqa: D102
        return self._service.dimensions

    async def embed(self, request: EmbeddingRequest) -> EmbeddingResponse:
        """Generate embeddings locally using Sentence Transformers.

        The ``input_type`` field on the request is inspected to choose
        between ``embed_query`` (for ``"query"`` / ``"search_query"``)
        and ``embed_documents`` (for everything else).
        """
        is_query = request.input_type in ("query", "search_query")

        if is_query and len(request.texts) == 1:
            # Single query — use dedicated query method
            vec = await asyncio.to_thread(
                self._service.embed_query, request.texts[0]
            )
            results = [
                EmbeddingResult(
                    index=0,
                    vector=vec,
                    dimensions=len(vec),
                )
            ]
        else:
            # Batch passage / multi-query — use documents method
            vectors = await asyncio.to_thread(
                self._service.embed_documents, request.texts
            )
            results = [
                EmbeddingResult(
                    index=i,
                    vector=vec,
                    dimensions=len(vec),
                )
                for i, vec in enumerate(vectors)
            ]

        return EmbeddingResponse(
            embeddings=results,
            model=request.model or self.default_model,
            provider=self.provider_name,
            dimensions=results[0].dimensions if results else self._service.dimensions,
            total_tokens=None,  # local inference — no token billing
        )
