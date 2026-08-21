"""Optional live provider smoke tests.

These tests execute actual network requests against live model providers ONLY when the
corresponding environment variable (e.g. GEMINI_API_KEY, GROQ_API_KEY) is explicitly provided.
Otherwise they are safely skipped during standard offline/CI test runs.
"""

import os
import pytest

from app.llm.adapters.gemini import GeminiAdapter
from app.llm.adapters.groq import GroqAdapter
from app.llm.adapters.huggingface import HuggingFaceAdapter
from app.llm.adapters.nvidia import NvidiaAdapter
from app.llm.types import LLMMessage, LLMRequest


@pytest.mark.skipif(not os.getenv("GEMINI_API_KEY"), reason="GEMINI_API_KEY not set in environment")
@pytest.mark.asyncio
async def test_live_gemini_smoke():
    """Live smoke test against Google Gemini API."""
    adapter = GeminiAdapter(api_key=os.getenv("GEMINI_API_KEY"))
    req = LLMRequest(
        messages=[LLMMessage(role="user", content="Respond with the single word: OK")],
        max_tokens=10,
    )
    res = await adapter.generate(req)
    assert res.content and len(res.content.strip()) > 0


@pytest.mark.skipif(not os.getenv("GROQ_API_KEY"), reason="GROQ_API_KEY not set in environment")
@pytest.mark.asyncio
async def test_live_groq_smoke():
    """Live smoke test against Groq API."""
    adapter = GroqAdapter(api_key=os.getenv("GROQ_API_KEY"))
    req = LLMRequest(
        messages=[LLMMessage(role="user", content="Respond with the single word: OK")],
        max_tokens=10,
    )
    res = await adapter.generate(req)
    assert res.content and len(res.content.strip()) > 0


@pytest.mark.skipif(not os.getenv("NVIDIA_API_KEY"), reason="NVIDIA_API_KEY not set in environment")
@pytest.mark.asyncio
async def test_live_nvidia_smoke():
    """Live smoke test against NVIDIA API."""
    adapter = NvidiaAdapter(api_key=os.getenv("NVIDIA_API_KEY"))
    req = LLMRequest(
        messages=[LLMMessage(role="user", content="Respond with the single word: OK")],
        max_tokens=10,
    )
    res = await adapter.generate(req)
    assert res.content and len(res.content.strip()) > 0


@pytest.mark.skipif(not os.getenv("HUGGINGFACE_API_KEY"), reason="HUGGINGFACE_API_KEY not set in environment")
@pytest.mark.asyncio
async def test_live_huggingface_smoke():
    """Live smoke test against Hugging Face API."""
    adapter = HuggingFaceAdapter(api_key=os.getenv("HUGGINGFACE_API_KEY"))
    req = LLMRequest(
        messages=[LLMMessage(role="user", content="Respond with the single word: OK")],
        max_tokens=10,
    )
    res = await adapter.generate(req)
    assert res.content and len(res.content.strip()) > 0
