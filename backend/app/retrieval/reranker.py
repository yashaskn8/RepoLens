"""Qwen3-Reranker neural cross-encoder client with clean RRF fallback."""

import logging
from typing import List, Optional, Tuple
import httpx

from app.core.config import get_settings
from app.retrieval.schemas import RerankCandidate

logger = logging.getLogger(__name__)


class QwenReranker:
    """Neural cross-encoder reranker for Qwen/Qwen3-Reranker-0.6B.
    
    Gracefully falls back to original candidate RRF scores if the service is unreachable
    or API credentials are unconfigured.
    """

    MODEL_ID: str = "Qwen/Qwen3-Reranker-0.6B"

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
    ):
        settings = get_settings()
        self.api_key = api_key or settings.HUGGINGFACE_API_KEY
        self.base_url = (base_url or settings.HUGGINGFACE_BASE_URL).rstrip("/")

    async def rerank(
        self,
        query: str,
        candidates: List[RerankCandidate],
    ) -> List[Tuple[str, Optional[float]]]:
        """Rerank candidates using Qwen3-Reranker.
        
        Returns:
            List of (chunk_id, reranked_score). If reranker is unavailable or fails,
            returns candidates in their initial RRF order with score=None.
        """
        if not candidates:
            return []

        if not self.api_key:
            logger.debug("Reranker API key is not configured; using initial RRF ranking.")
            return [(c.chunk_id, None) for c in candidates]

        settings = get_settings()
        timeout = min(15.0, settings.LLM_DEFAULT_TIMEOUT)

        # Build payload for standard reranking endpoint
        payload = {
            "model": self.MODEL_ID,
            "query": query,
            "texts": [c.content for c in candidates],
        }
        url = f"{self.base_url}/rerank"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }

        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.post(url, json=payload, headers=headers)

            if response.status_code != 200:
                logger.warning(
                    "Reranker returned HTTP %d: %s. Falling back to RRF.",
                    response.status_code,
                    response.text[:200],
                )
                return [(c.chunk_id, None) for c in candidates]

            data = response.json()
            # Standard rerank response format: list of objects with "index" and "score" / "relevance_score"
            results = data.get("results") or data.get("data") or data
            if not isinstance(results, list):
                logger.warning("Reranker returned unexpected shape. Falling back to RRF.")
                return [(c.chunk_id, None) for c in candidates]

            scored_candidates: List[Tuple[str, float]] = []
            for item in results:
                idx = item.get("index")
                score = float(item.get("relevance_score", item.get("score", 0.0)))
                if idx is not None and 0 <= idx < len(candidates):
                    scored_candidates.append((candidates[idx].chunk_id, score))

            if not scored_candidates:
                return [(c.chunk_id, None) for c in candidates]

            # Sort by neural rerank score descending
            scored_candidates.sort(key=lambda item: (-item[1], item[0]))
            return [(cid, score) for cid, score in scored_candidates]

        except Exception as exc:
            logger.warning("Neural reranking failed with error: %s. Falling back cleanly to RRF.", str(exc))
            return [(c.chunk_id, None) for c in candidates]
