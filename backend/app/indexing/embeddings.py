"""Provider-neutral embedding abstraction and concrete adapters."""

from abc import ABC, abstractmethod
import logging
import time
from typing import List, Optional

import httpx

from app.core.config import get_settings
from app.indexing.schemas import (
    EmbeddingRequest,
    EmbeddingResponse,
    EmbeddingResult,
)

logger = logging.getLogger(__name__)


class EmbeddingProvider(ABC):
    """Abstract interface for embedding providers.

    Concrete adapters must implement ``embed()`` which accepts
    an ``EmbeddingRequest`` and returns an ``EmbeddingResponse``.
    """

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Human-readable provider identifier."""

    @property
    @abstractmethod
    def default_model(self) -> str:
        """Default embedding model ID for this provider."""

    @property
    @abstractmethod
    def dimensions(self) -> int:
        """Output vector dimensionality for the default model."""

    @abstractmethod
    async def embed(self, request: EmbeddingRequest) -> EmbeddingResponse:
        """Generate embedding vectors for the given texts."""


# ---------------------------------------------------------------------------
# NVIDIA NV-EmbedCode Adapter (Primary)
# ---------------------------------------------------------------------------

class NvidiaEmbeddingAdapter(EmbeddingProvider):
    """NVIDIA NIM embedding adapter for nvidia/nv-embedcode-7b-v1.

    Uses the OpenAI-compatible ``/embeddings`` endpoint on the
    NVIDIA NIM base URL with ``input_type`` passthrough.
    """

    MODEL_ID: str = "nvidia/nv-embedcode-7b-v1"
    DIMENSIONS: int = 4096

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
    ):
        settings = get_settings()
        self.api_key = api_key or settings.NVIDIA_API_KEY
        self.base_url = (base_url or settings.NVIDIA_BASE_URL).rstrip("/")

    @property
    def provider_name(self) -> str:
        return "nvidia"

    @property
    def default_model(self) -> str:
        return self.MODEL_ID

    @property
    def dimensions(self) -> int:
        return self.DIMENSIONS

    async def embed(self, request: EmbeddingRequest) -> EmbeddingResponse:
        """Call NVIDIA NIM /embeddings endpoint."""
        model = request.model or self.default_model
        url = f"{self.base_url}/embeddings"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }
        payload = {
            "model": model,
            "input": request.texts,
            "input_type": request.input_type,
            "encoding_format": "float",
        }

        settings = get_settings()
        timeout = settings.LLM_DEFAULT_TIMEOUT

        start = time.perf_counter()
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(url, json=payload, headers=headers)

        elapsed_ms = (time.perf_counter() - start) * 1000.0

        if resp.status_code != 200:
            raise RuntimeError(
                f"NVIDIA embedding request failed ({resp.status_code}): {resp.text}"
            )

        data = resp.json()
        embeddings = []
        for item in data.get("data", []):
            vec = item["embedding"]
            embeddings.append(
                EmbeddingResult(
                    index=item["index"],
                    vector=vec,
                    dimensions=len(vec),
                )
            )

        usage = data.get("usage", {})
        return EmbeddingResponse(
            embeddings=embeddings,
            model=data.get("model", model),
            provider=self.provider_name,
            dimensions=embeddings[0].dimensions if embeddings else self.DIMENSIONS,
            total_tokens=usage.get("total_tokens"),
        )


# ---------------------------------------------------------------------------
# Hugging Face Qwen3-Embedding Fallback Adapter
# ---------------------------------------------------------------------------

class HuggingFaceEmbeddingAdapter(EmbeddingProvider):
    """Hugging Face Inference API adapter for Qwen/Qwen3-Embedding-0.6B fallback."""

    MODEL_ID: str = "Qwen/Qwen3-Embedding-0.6B"
    DIMENSIONS: int = 1024

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
    ):
        settings = get_settings()
        self.api_key = api_key or settings.HUGGINGFACE_API_KEY
        self.base_url = (base_url or settings.HUGGINGFACE_BASE_URL).rstrip("/")

    @property
    def provider_name(self) -> str:
        return "huggingface"

    @property
    def default_model(self) -> str:
        return self.MODEL_ID

    @property
    def dimensions(self) -> int:
        return self.DIMENSIONS

    async def embed(self, request: EmbeddingRequest) -> EmbeddingResponse:
        """Call Hugging Face Inference API /embeddings endpoint."""
        model = request.model or self.default_model
        url = f"{self.base_url}/embeddings"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }
        payload = {
            "model": model,
            "input": request.texts,
            "encoding_format": "float",
        }

        settings = get_settings()
        timeout = settings.LLM_DEFAULT_TIMEOUT

        start = time.perf_counter()
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(url, json=payload, headers=headers)

        elapsed_ms = (time.perf_counter() - start) * 1000.0

        if resp.status_code != 200:
            raise RuntimeError(
                f"HuggingFace embedding request failed ({resp.status_code}): {resp.text}"
            )

        data = resp.json()
        embeddings = []
        for item in data.get("data", []):
            vec = item["embedding"]
            embeddings.append(
                EmbeddingResult(
                    index=item["index"],
                    vector=vec,
                    dimensions=len(vec),
                )
            )

        usage = data.get("usage", {})
        return EmbeddingResponse(
            embeddings=embeddings,
            model=data.get("model", model),
            provider=self.provider_name,
            dimensions=embeddings[0].dimensions if embeddings else self.DIMENSIONS,
            total_tokens=usage.get("total_tokens"),
        )
