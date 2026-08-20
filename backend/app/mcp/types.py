"""Type definitions and schemas for the Model Context Protocol (MCP) tool layer."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class MCPToolDefinition(BaseModel):
    """Metadata schema defining an MCP tool."""

    name: str = Field(..., description="Unique tool name")
    description: str = Field(..., description="Human and LLM-readable description of what the tool does")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="JSON Schema parameter specifications")


class MCPToolCallRequest(BaseModel):
    """Invocations sent to the MCP server."""

    tool_name: str = Field(..., description="Name of the tool to invoke")
    arguments: Dict[str, Any] = Field(default_factory=dict, description="Arguments dictionary matching tool parameter schema")


class MCPToolCallResponse(BaseModel):
    """Result returned by an MCP tool invocation."""

    tool_name: str = Field(..., description="Name of the tool that executed")
    is_error: bool = Field(default=False, description="True if execution resulted in an error")
    content: Any = Field(default=None, description="Structured payload or serialized string")
    error_message: Optional[str] = Field(default=None, description="Error message if is_error is True")
