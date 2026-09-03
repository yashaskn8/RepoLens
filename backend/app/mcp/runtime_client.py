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
from app.mcp.server import MCPRepositoryServer
from app.security.redaction import redact_secrets

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class MCPNormalizedResult:
    """Normalized, transport-independent representation of an MCP tool invocation."""

    tool_name: str
    is_error: bool
    content: Any
    error_message: Optional[str] = None
    raw_text: Optional[str] = None


class MCPRuntimeClient:
    """Official in-process MCP runtime client connecting to the canonical RepoLens protocol server.

    Guarantees:
    - Exercises official in-process MCP protocol/session transport over AnyIO memory streams.
    - Lazy connection: session is established only when explicitly requested or on first tool call.
    - Discovers tools via official list_tools() and caches them immutably.
    - Enforces invocation timeouts and sanitizes all external error strings with redact_secrets.
    - Never exposes raw ClientSession or protocol wire objects to LangGraph state or checkpoints.
    - Zero subprocesses, zero network sockets, zero Docker.
    """

    def __init__(
        self,
        repo_server: MCPRepositoryServer,
        server_name: str = "repolens-repository-server",
        default_timeout_seconds: float = 10.0,
    ):
        self.repo_server = repo_server
        self.server_name = server_name
        self.default_timeout_seconds = default_timeout_seconds

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

    async def ensure_connected(self) -> None:
        """Establish the official in-process MCP session lazily if not already connected."""
        if self._session is not None:
            return

        async with self._lock:
            if self._session is not None:
                return

            try:
                if self._protocol_server is None:
                    self._protocol_server = create_mcp_protocol_server(
                        self.repo_server,
                        server_name=self.server_name,
                    )

                ready_event = asyncio.Event()
                stop_event = asyncio.Event()
                session_holder: List[Any] = []
                init_error: List[Exception] = []

                async def _session_runner() -> None:
                    try:
                        async with create_connected_server_and_client_session(self._protocol_server) as session:
                            session_holder.append(session)
                            ready_event.set()
                            await stop_event.wait()
                    except Exception as exc:
                        init_error.append(exc)
                        ready_event.set()

                task = asyncio.create_task(_session_runner())
                await ready_event.wait()

                if init_error or not session_holder:
                    err = init_error[0] if init_error else RuntimeError("MCP session failed to initialize.")
                    safe_err = redact_secrets(str(err))[:512]
                    logger.error("Failed to initialize MCP protocol session: %s", safe_err)
                    stop_event.set()
                    try:
                        await asyncio.wait_for(task, timeout=2.0)
                    except Exception:
                        pass
                    raise RuntimeError(f"MCP protocol session initialization failed: {safe_err}") from err

                session = session_holder[0]
                tools_res = await session.list_tools()
                discovered = {t.name: t for t in tools_res.tools}

                self._session_task = task
                self._stop_event = stop_event
                self._session = session
                self._discovered_tools = MappingProxyType(discovered)
                logger.info("Initialized lazy in-process MCP session with %d discovered tools.", len(discovered))

            except Exception as exc:
                safe_err = redact_secrets(str(exc))[:512]
                logger.error("Failed to initialize MCP protocol session: %s", safe_err)
                raise RuntimeError(f"MCP protocol session initialization failed: {safe_err}") from exc

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
        """Execute an MCP tool over the official session transport with bounded timeout."""
        await self.ensure_connected()

        if self._session is None or self._discovered_tools is None:
            return MCPNormalizedResult(
                tool_name=name,
                is_error=True,
                content=None,
                error_message="MCP_PROTOCOL_ERROR: Session is not available.",
            )

        if name not in self._discovered_tools:
            return MCPNormalizedResult(
                tool_name=name,
                is_error=True,
                content=None,
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
                error_message=f"MCP_TOOL_TIMEOUT: Tool '{name}' exceeded timeout of {timeout}s.",
            )
        except Exception as exc:
            safe_err = redact_secrets(str(exc))[:512]
            logger.error("MCP tool '%s' invocation error: %s", name, safe_err)
            return MCPNormalizedResult(
                tool_name=name,
                is_error=True,
                content=None,
                error_message=f"MCP_TOOL_FAILED: {safe_err}",
            )

    def _normalize_result(self, tool_name: str, result: mcp_types.CallToolResult) -> MCPNormalizedResult:
        """Normalize CallToolResult into a safe, parsed, transport-independent structure."""
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
                error_message=redact_secrets(err_text)[:1024],
                raw_text=err_text,
            )

        # Handle structured content if present in modern MCP responses
        structured = getattr(result, "structuredContent", None) or getattr(result, "structured_content", None)
        if structured is not None:
            return MCPNormalizedResult(
                tool_name=tool_name,
                is_error=False,
                content=structured,
                raw_text=json.dumps(structured, default=str),
            )

        # Process textual content blocks
        text_blocks: List[str] = []
        if result.content:
            for block in result.content:
                if getattr(block, "type", "") == "text" and hasattr(block, "text"):
                    text_blocks.append(block.text)

        joined_text = "\n".join(text_blocks).strip() if text_blocks else ""

        # Attempt JSON decoding if the output is JSON
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
                    self._stop_event.set()
                    await asyncio.wait_for(self._session_task, timeout=5.0)
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
