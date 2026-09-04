"""Evidence-scoped AI response caching and bounded in-process single-flight."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import hashlib
import inspect
import json
from typing import Awaitable, Callable, Generic, Protocol, TypeVar

from app.core.config import get_settings
from app.indexing.embeddings import EmbeddingProvider
from app.indexing.schemas import EmbeddingRequest
from app.llm.types import LLMRequest, LLMResponse, ModelCapability, TaskPolicy
from app.retrieval.vector_index import cosine_similarity
from app.services.redis_service import RedisService


class AICacheStore(Protocol):
    @property
    def is_available(self) -> bool: ...

    async def get(self, key: str, namespace: str = "cache"): ...

    async def set(self, key: str, value, ttl: int | None = None, namespace: str = "cache") -> bool: ...


CacheEventSink = Callable[[str, LLMRequest], object]

_SAFE_SEMANTIC_TASKS = frozenset(
    {"classification", "summary", "explanation", "query_rewrite", "informational"}
)
_SEMANTIC_DENY_CAPABILITIES = frozenset(
    {
        ModelCapability.SECURITY_REASONING,
        ModelCapability.VERIFICATION,
        ModelCapability.PATCH_GENERATION,
        ModelCapability.CODE_REASONING,
        ModelCapability.DEEP_REASONING,
    }
)
_SEMANTIC_DENY_POLICIES = frozenset(
    {
        TaskPolicy.SECURITY_REASONING,
        TaskPolicy.VERIFICATION,
        TaskPolicy.PATCH_GENERATION,
        TaskPolicy.PATCH_CRITIC,
        TaskPolicy.FIX_PLANNING,
        TaskPolicy.BUG_REASONING,
        TaskPolicy.CHANGE_REVIEW,
    }
)


@dataclass(frozen=True)
class CacheLookup:
    response: LLMResponse
    kind: str


class AIResponseCache:
    """Small Redis-backed cache whose keys include authority and evidence identity."""

    VERSION = "ai-response-cache/1.0"

    def __init__(
        self,
        store: AICacheStore | None = None,
        *,
        embedding_provider: EmbeddingProvider | None = None,
        event_sink: CacheEventSink | None = None,
    ) -> None:
        self.store = store or RedisService()
        self._embedding_provider = embedding_provider
        self._event_sink = event_sink

    def can_coalesce(self, request: LLMRequest) -> bool:
        """Only share deterministic work that meets the exact-cache authority contract."""
        return self.exact_cache_allowed(request)

    def exact_cache_allowed(self, request: LLMRequest) -> bool:
        if request.cache_mode == "disabled" or request.temperature != 0:
            return False
        lineage = request.lineage
        if not lineage.tenant_id or lineage.prompt_template_version == "unspecified":
            return False
        if request.output_schema is not None and not lineage.output_schema_version:
            return False
        if request.capability not in {
            ModelCapability.CLASSIFICATION,
            ModelCapability.STRUCTURED_EXTRACTION,
        } and not lineage.evidence_digest:
            return False
        return True

    def semantic_cache_allowed(self, request: LLMRequest) -> bool:
        settings = get_settings()
        return bool(
            settings.AI_SEMANTIC_CACHE_ENABLED
            and request.cache_mode == "semantic"
            and request.cache_task in _SAFE_SEMANTIC_TASKS
            and request.capability not in _SEMANTIC_DENY_CAPABILITIES
            and request.task_policy not in _SEMANTIC_DENY_POLICIES
            and self.exact_cache_allowed(request)
        )

    def request_key(self, request: LLMRequest, routing_identity: str) -> str:
        payload = self._identity_payload(request, routing_identity, include_messages=True)
        return f"ai:exact:{self._digest(payload)}"

    def semantic_bucket_key(self, request: LLMRequest, routing_identity: str) -> str:
        payload = self._identity_payload(request, routing_identity, include_messages=False)
        return f"ai:semantic:{self._digest(payload)}"

    async def lookup(self, request: LLMRequest, routing_identity: str) -> CacheLookup | None:
        if not self.exact_cache_allowed(request) or not self.store.is_available:
            return None
        try:
            exact = await self.store.get(
                self.request_key(request, routing_identity), namespace="cache"
            )
        except Exception:
            await self.record_event("cache_error", request)
            return None
        if isinstance(exact, dict):
            response = self._response_from_cache(exact, kind="exact")
            if response is not None:
                await self.record_event("exact_hit", request)
                return CacheLookup(response=response, kind="exact")
        await self.record_event("exact_miss", request)

        if self.semantic_cache_allowed(request):
            try:
                semantic = await self._semantic_lookup(request, routing_identity)
            except Exception:
                await self.record_event("cache_error", request)
                return None
            if semantic is not None:
                await self.record_event("semantic_hit", request)
                return CacheLookup(response=semantic, kind="semantic")
            await self.record_event("semantic_miss", request)
        return None

    async def store_response(
        self,
        request: LLMRequest,
        routing_identity: str,
        response: LLMResponse,
    ) -> None:
        if not self.exact_cache_allowed(request) or not self.store.is_available:
            return
        settings = get_settings()
        payload = self._safe_response_payload(response)
        try:
            await self.store.set(
                self.request_key(request, routing_identity),
                payload,
                ttl=settings.AI_EXACT_CACHE_TTL_SECONDS,
                namespace="cache",
            )
            if self.semantic_cache_allowed(request):
                await self._semantic_store(request, routing_identity, payload)
        except Exception:
            await self.record_event("cache_error", request)

    async def record_event(self, event: str, request: LLMRequest) -> None:
        if self._event_sink is None:
            return
        try:
            result = self._event_sink(event, request)
            if inspect.isawaitable(result):
                await result
        except Exception:
            # Metrics can never become an execution dependency.
            return

    async def _semantic_lookup(
        self, request: LLMRequest, routing_identity: str
    ) -> LLMResponse | None:
        provider = self._get_embedding_provider()
        if provider is None:
            return None
        entries = await self.store.get(
            self.semantic_bucket_key(request, routing_identity), namespace="cache"
        )
        if not isinstance(entries, list) or not entries:
            return None
        vector = await self._embed_request(provider, request)
        if vector is None:
            return None
        threshold = get_settings().AI_SEMANTIC_CACHE_SIMILARITY_THRESHOLD
        best: tuple[float, dict] | None = None
        for entry in entries:
            if not isinstance(entry, dict) or not isinstance(entry.get("vector"), list):
                continue
            score = cosine_similarity(vector, entry["vector"])
            if score >= threshold and (best is None or score > best[0]):
                best = (score, entry)
        if best is None:
            return None
        response = self._response_from_cache(best[1].get("response"), kind="semantic")
        if response is not None:
            response.metadata.extra_metadata["semantic_similarity"] = round(best[0], 6)
            response.metadata.extra_metadata["authoritative_cache_result"] = False
        return response

    async def _semantic_store(
        self,
        request: LLMRequest,
        routing_identity: str,
        response_payload: dict,
    ) -> None:
        provider = self._get_embedding_provider()
        if provider is None:
            return
        vector = await self._embed_request(provider, request)
        if vector is None:
            return
        key = self.semantic_bucket_key(request, routing_identity)
        existing = await self.store.get(key, namespace="cache")
        entries = list(existing) if isinstance(existing, list) else []
        entries = [entry for entry in entries if isinstance(entry, dict)]
        entries.append({"vector": vector, "response": response_payload})
        max_entries = get_settings().AI_SEMANTIC_CACHE_MAX_ENTRIES
        await self.store.set(
            key,
            entries[-max_entries:],
            ttl=get_settings().AI_SEMANTIC_CACHE_TTL_SECONDS,
            namespace="cache",
        )

    async def _embed_request(
        self, provider: EmbeddingProvider, request: LLMRequest
    ) -> list[float] | None:
        try:
            text = "\n".join(
                f"{message.role}:{' '.join(message.content.split())}"
                for message in request.messages
            )
            response = await provider.embed(
                EmbeddingRequest(
                    texts=[text], input_type="query", model=provider.default_model
                )
            )
            return response.embeddings[0].vector if response.embeddings else None
        except Exception:
            return None

    def _get_embedding_provider(self) -> EmbeddingProvider | None:
        if self._embedding_provider is not None:
            return self._embedding_provider
        if not get_settings().LOCAL_EMBEDDING_ENABLED:
            return None
        try:
            from app.embeddings.adapter import LocalEmbeddingAdapter

            self._embedding_provider = LocalEmbeddingAdapter()
        except Exception:
            return None
        return self._embedding_provider

    @staticmethod
    def _safe_response_payload(response: LLMResponse) -> dict:
        payload = response.model_dump(mode="json")
        extra = dict(payload.get("metadata", {}).get("extra_metadata") or {})
        extra.pop("ai_execution_id", None)
        extra.pop("quota_reservation_id", None)
        payload["metadata"]["extra_metadata"] = extra
        return payload

    @staticmethod
    def _response_from_cache(payload, *, kind: str) -> LLMResponse | None:
        if not isinstance(payload, dict):
            return None
        try:
            response = LLMResponse.model_validate(payload).model_copy(deep=True)
        except Exception:
            return None
        extra = dict(response.metadata.extra_metadata or {})
        extra.update(
            {
                "cache_hit": True,
                "cache_kind": kind,
                "provider_call_avoided": True,
            }
        )
        response.metadata.extra_metadata = extra
        return response

    def _identity_payload(
        self,
        request: LLMRequest,
        routing_identity: str,
        *,
        include_messages: bool,
    ) -> dict:
        lineage = request.lineage
        payload = {
            "cache_version": self.VERSION,
            "tenant_id": lineage.tenant_id,
            "capability": request.capability.value if request.capability else None,
            "task_policy": request.task_policy.value if request.task_policy else None,
            "cache_task": request.cache_task,
            "prompt_template_version": lineage.prompt_template_version,
            "output_schema_version": lineage.output_schema_version,
            "evidence_digest": lineage.evidence_digest,
            "policy_snapshot_id": lineage.policy_snapshot_id,
            "provider": request.provider.value if request.provider else None,
            "model": request.model,
            "excluded_providers": sorted(item.value for item in request.excluded_providers),
            "excluded_models": sorted(request.excluded_models),
            "temperature": request.temperature,
            "max_tokens": request.max_tokens,
            "json_mode": request.json_mode,
            "output_schema": request.output_schema,
            "confidence_threshold": request.confidence_threshold,
            "allow_escalation": request.allow_escalation,
            "timeout_seconds": request.timeout_seconds,
            "extra_params": request.extra_params,
            "context_metrics": (
                request.context_metrics.model_dump(mode="json")
                if request.context_metrics is not None
                else None
            ),
            "routing_identity": routing_identity,
        }
        if include_messages:
            payload["messages"] = [
                {"role": item.role, "content": " ".join(item.content.split())}
                for item in request.messages
            ]
        return payload

    @staticmethod
    def _digest(payload: dict) -> str:
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()


T = TypeVar("T")


class SingleFlight(Generic[T]):
    """Coalesce identical in-process work without a durable/distributed lock."""

    def __init__(self, max_entries: int = 256) -> None:
        self.max_entries = max(1, max_entries)
        self._lock = asyncio.Lock()
        self._tasks: dict[str, asyncio.Task[T]] = {}

    @property
    def active_count(self) -> int:
        return len(self._tasks)

    async def run(self, key: str, factory: Callable[[], Awaitable[T]]) -> tuple[T, bool]:
        bypass = False
        async with self._lock:
            task = self._tasks.get(key)
            shared = task is not None
            if task is None:
                if len(self._tasks) >= self.max_entries:
                    bypass = True
                else:
                    task = asyncio.create_task(factory())
                    self._tasks[key] = task
                    task.add_done_callback(
                        lambda completed, request_key=key: self._on_done(
                            request_key, completed
                        )
                    )
        if bypass:
            return await factory(), False
        assert task is not None
        return await asyncio.shield(task), shared

    def _on_done(self, key: str, task: asyncio.Task[T]) -> None:
        # Retrieve abandoned exceptions so a cancelled waiter cannot leak an
        # unobserved-task warning. Awaiting waiters still receive the exception.
        if not task.cancelled():
            task.exception()
        if self._tasks.get(key) is task:
            self._tasks.pop(key, None)


__all__ = ["AIResponseCache", "CacheLookup", "SingleFlight"]
