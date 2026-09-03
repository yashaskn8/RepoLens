"""Official in-process MCP client managing session lifecycle, tool discovery, and execution."""

import asyncio
from dataclasses import dataclass
import json
import logging
from types import MappingProxyType
from typing import Any, Dict, List, Optional

from mcp.server.lowlevel import Server
from mcp.shared.memory import create_connected_server_and_client_session
import mcp.types as mcp_types

from app.mcp.adapter import create_mcp_protocol_server
from app.mcp.constants import (
    DEFAULT_MCP_INITIALIZATION_TIMEOUT_SECONDS,
    DEFAULT_MCP_TOOL_TIMEOUT_SECONDS,
    MAX_MCP_CLIENT_RESULT_BYTES,
)
from app.mcp.server import MCPRepositoryServer
from app.security.redaction import redact_secrets

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class MCPNormalizedResult:
    """Normalized, transport-independent representation of an MCP tool invocation."""

    tool_name: str
    is_error: bool
    content: Any
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    raw_text: Optional[str] = None


class MCPRuntimeClient:
    """Official in-process MCP runtime client connecting to the canonical RepoLens protocol server.

    Guarantees:
    - Exercises official in-process MCP protocol/session transport over AnyIO memory streams.
    - Lazy connection: session is established only when explicitly requested or on first tool call.
    - Discovers tools via official list_tools() and caches them immutably.
    - Enforces bounded startup and tool timeouts; cleans up local tasks and cancel scopes without leaks.
    - Enforces hard UTF-8 byte result size ceiling before string joining and JSON parsing.
    - Normalizes startup and execution failures into structured MCPNormalizedResult error codes.
    - Never exposes raw ClientSession or protocol wire objects to LangGraph state or checkpoints.
    - Zero subprocesses, zero network sockets, zero Docker.
    """

    def __init__(
        self,
        repo_server: MCPRepositoryServer,
        server_name: str = "repolens-repository-server",
        default_timeout_seconds: float = DEFAULT_MCP_TOOL_TIMEOUT_SECONDS,
        init_timeout_seconds: float = DEFAULT_MCP_INITIALIZATION_TIMEOUT_SECONDS,
    ):
        self.repo_server = repo_server
        self.server_name = server_name
        self.default_timeout_seconds = default_timeout_seconds
        self.init_timeout_seconds = init_timeout_seconds

        self._protocol_server: Optional[Server] = None
        self._session_task: Optional[asyncio.Task] = None
        self._stop_event: Optional[asyncio.Event] = None
        self._session: Optional[Any] = None
        self._discovered_tools: Optional[MappingProxyType[str, mcp_types.Tool]] = None
        self._lock = asyncio.Lock()

    @property
    def is_connected(self) -> bool:
        """Return whether an active MCP session is established."""
        return self._session is not None

    @staticmethod
    async def _cleanup_local_task(
        task: Optional[asyncio.Task],
        stop_event: Optional[asyncio.Event],
        cleanup_timeout_seconds: float = 2.0,
    ) -> None:
        """Safely terminate and await an uncommitted or aborting session runner task."""
        if stop_event is not None:
            stop_event.set()
        if task is not None and not task.done():
            try:
                await asyncio.wait_for(asyncio.shield(task), timeout=cleanup_timeout_seconds)
            except (asyncio.TimeoutError, asyncio.CancelledError, Exception):
                task.cancel()
                try:
                    await asyncio.wait_for(task, timeout=1.0)
                except (asyncio.CancelledError, Exception):
                    pass

    async def ensure_connected(self) -> None:
        """Establish the official in-process MCP session lazily with bounded startup and leak-free cleanup."""
        if self._session is not None and self._discovered_tools is not None:
            return

        async with self._lock:
            if self._session is not None and self._discovered_tools is not None:
                return

            local_task: Optional[asyncio.Task] = None
            local_stop: Optional[asyncio.Event] = None
            committed: bool = False

            try:
                if self._protocol_server is None:
                    self._protocol_server = create_mcp_protocol_server(
                        self.repo_server,
                        server_name=self.server_name,
                    )

                local_stop = asyncio.Event()
                ready_event = asyncio.Event()
                session_holder: List[Any] = []
                init_error: List[Exception] = []

                async def _session_runner() -> None:
                    try:
                        async with create_connected_server_and_client_session(self._protocol_server) as session:
                            session_holder.append(session)
                            ready_event.set()
                            await local_stop.wait()
                    except Exception as exc:
                        init_error.append(exc)
                        ready_event.set()

                async def _startup_sequence() -> MappingProxyType[str, mcp_types.Tool]:
                    nonlocal local_task
                    local_task = asyncio.create_task(_session_runner())
                    await ready_event.wait()

                    if init_error or not session_holder:
                        err = init_error[0] if init_error else RuntimeError("MCP session failed to initialize.")
                        raise err

                    session = session_holder[0]
                    tools_res = await session.list_tools()
                    discovered = {t.name: t for t in tools_res.tools}
                    return MappingProxyType(discovered)

                discovered_tools = await asyncio.wait_for(
                    _startup_sequence(),
                    timeout=self.init_timeout_seconds,
                )

                # Commit to object state only after entire startup and discovery succeed
                self._session_task = local_task
                self._stop_event = local_stop
                self._session = session_holder[0]
                self._discovered_tools = discovered_tools
                committed = True
                logger.info("Initialized lazy in-process MCP session with %d discovered tools.", len(discovered_tools))

            except asyncio.CancelledError:
                self._session_task = None
                self._stop_event = None
                self._session = None
                self._discovered_tools = None
                if not committed:
                    await self._cleanup_local_task(local_task, local_stop)
                raise

            except Exception as exc:
                self._session_task = None
                self._stop_event = None
                self._session = None
                self._discovered_tools = None
                if not committed:
                    await self._cleanup_local_task(local_task, local_stop)
                safe_err = redact_secrets(str(exc))[:512]
                logger.error("Failed to initialize MCP protocol session: %s", safe_err)
                raise RuntimeError("MCP protocol session initialization failed.") from exc

    def get_discovered_tools(self) -> MappingProxyType[str, mcp_types.Tool]:
        """Retrieve the immutable map of discovered MCP tools."""
        if self._discovered_tools is None:
            raise RuntimeError("MCP client is not connected. Call ensure_connected() first.")
        return self._discovered_tools

    async def call_tool(
        self,
        name: str,
        arguments: Optional[Dict[str, Any]] = None,
        timeout_seconds: Optional[float] = None,
    ) -> MCPNormalizedResult:
        """Execute an MCP tool over the official session transport with bounded timeout and normalized errors."""
        try:
            await self.ensure_connected()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            safe_err = redact_secrets(str(exc))[:512]
            logger.error("MCP runtime connection failed for tool '%s': %s", name, safe_err)
            return MCPNormalizedResult(
                tool_name=name,
                is_error=True,
                content=None,
                error_code="MCP_PROTOCOL_ERROR",
                error_message="MCP runtime connection failed.",
            )

        if self._session is None or self._discovered_tools is None:
            return MCPNormalizedResult(
                tool_name=name,
                is_error=True,
                content=None,
                error_code="MCP_PROTOCOL_ERROR",
                error_message="MCP_PROTOCOL_ERROR: Session is not available.",
            )

        if name not in self._discovered_tools:
            return MCPNormalizedResult(
                tool_name=name,
                is_error=True,
                content=None,
                error_code="MCP_TOOL_NOT_FOUND",
                error_message=f"MCP_TOOL_NOT_FOUND: Tool '{name}' is not exposed by server.",
            )

        timeout = timeout_seconds if timeout_seconds is not None else self.default_timeout_seconds
        args = arguments if arguments is not None else {}

        try:
            async with asyncio.timeout(timeout):
                raw_res = await self._session.call_tool(name, args)
                return self._normalize_result(name, raw_res)

        except asyncio.TimeoutError:
            logger.warning("MCP tool '%s' timed out after %.1fs", name, timeout)
            return MCPNormalizedResult(
                tool_name=name,
                is_error=True,
                content=None,
                error_code="MCP_TOOL_TIMEOUT",
                error_message=f"MCP_TOOL_TIMEOUT: Tool '{name}' exceeded timeout of {timeout}s.",
            )
        except Exception as exc:
            safe_err = redact_secrets(str(exc))[:512]
            logger.error("MCP tool '%s' invocation error: %s", name, safe_err)
            return MCPNormalizedResult(
                tool_name=name,
                is_error=True,
                content=None,
                error_code="MCP_TOOL_FAILED",
                error_message=f"MCP_TOOL_FAILED: {safe_err}",
            )

    def _normalize_result(self, tool_name: str, result: mcp_types.CallToolResult) -> MCPNormalizedResult:
        """Normalize CallToolResult into a safe, parsed, transport-independent structure enforcing UTF-8 bounds."""
        if result.isError:
            err_text = ""
            if result.content:
                text_parts = [c.text for c in result.content if getattr(c, "type", "") == "text" and hasattr(c, "text")]
                err_text = "\n".join(text_parts).strip()
            if not err_text:
                err_text = f"Tool '{tool_name}' returned error with no details."
            return MCPNormalizedResult(
                tool_name=tool_name,
                is_error=True,
                content=None,
                error_code="MCP_TOOL_FAILED",
                error_message=redact_secrets(err_text)[:1024],
                raw_text=err_text,
            )

        # 1. Handle structured content with deterministic UTF-8 size measurement
        structured = getattr(result, "structuredContent", None) or getattr(result, "structured_content", None)
        if structured is not None:
            serialized = json.dumps(structured, separators=(",", ":"), ensure_ascii=False, default=str)
            serialized_bytes = len(serialized.encode("utf-8"))
            if serialized_bytes > MAX_MCP_CLIENT_RESULT_BYTES:
                return MCPNormalizedResult(
                    tool_name=tool_name,
                    is_error=True,
                    content=None,
                    error_code="MCP_RESULT_TOO_LARGE",
                    error_message="MCP response exceeded the maximum allowed result size.",
                    raw_text="",
                )
            return MCPNormalizedResult(
                tool_name=tool_name,
                is_error=False,
                content=structured,
                raw_text=serialized,
            )

        # 2. Process textual content blocks incrementally tracking aggregate UTF-8 bytes
        total_utf8_bytes = 0
        text_blocks: List[str] = []
        if result.content:
            for block in result.content:
                if getattr(block, "type", "") == "text" and hasattr(block, "text") and block.text:
                    b_text = str(block.text)
                    b_bytes = len(b_text.encode("utf-8"))
                    sep_bytes = 1 if text_blocks else 0
                    if total_utf8_bytes + sep_bytes + b_bytes > MAX_MCP_CLIENT_RESULT_BYTES:
                        return MCPNormalizedResult(
                            tool_name=tool_name,
                            is_error=True,
                            content=None,
                            error_code="MCP_RESULT_TOO_LARGE",
                            error_message="MCP response exceeded the maximum allowed result size.",
                            raw_text="",
                        )
                    total_utf8_bytes += sep_bytes + b_bytes
                    text_blocks.append(b_text)

        joined_text = "\n".join(text_blocks).strip() if text_blocks else ""

        # Attempt JSON decoding if the output is formatted as JSON
        parsed_content: Any = joined_text
        if joined_text.startswith(("{", "[")):
            try:
                parsed_content = json.loads(joined_text)
            except Exception:
                parsed_content = joined_text

        return MCPNormalizedResult(
            tool_name=tool_name,
            is_error=False,
            content=parsed_content,
            raw_text=joined_text,
        )

    async def aclose(self) -> None:
        """Clean up the active MCP session and transport streams."""
        async with self._lock:
            if self._stop_event is not None and self._session_task is not None:
                try:
                    await self._cleanup_local_task(self._session_task, self._stop_event, cleanup_timeout_seconds=2.0)
                except Exception as exc:
                    logger.debug("Error closing MCP session: %s", redact_secrets(str(exc))[:256])
                finally:
                    self._session_task = None
                    self._stop_event = None
                    self._session = None
                    self._discovered_tools = None
                    logger.debug("Closed MCP session.")

    async def __aenter__(self) -> "MCPRuntimeClient":
        await self.ensure_connected()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.aclose()
