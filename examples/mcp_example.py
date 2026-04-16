"""AgentShield + MCP (Model Context Protocol) integration example.

Wraps an MCP tool server so that every tool call passes through AgentShield
before execution.

Requires:  pip install agentshield[mcp]
           (or: pip install agentshield mcp)

Run:  python examples/mcp_example.py
"""

from __future__ import annotations

import asyncio
from typing import Any

try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import TextContent, Tool
except ImportError:
    raise SystemExit(
        "MCP SDK not installed. Run:  pip install agentshield[mcp]\n"
        "  or:  pip install mcp"
    )

from agentshield import Shield, ToolCallBlocked, ToolCallContext

# ---------------------------------------------------------------------------
# Shield setup
# ---------------------------------------------------------------------------

shield = Shield(mode="enforce")

# ---------------------------------------------------------------------------
# MCP Server
# ---------------------------------------------------------------------------

app = Server("agentshield-example")


@app.list_tools()
async def list_tools() -> list[Tool]:
    """Advertise available tools to the MCP client."""
    return [
        Tool(
            name="execute_sql",
            description="Run a read-only SQL query",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "SQL query to execute"},
                },
                "required": ["query"],
            },
        ),
        Tool(
            name="read_file",
            description="Read a file from the workspace",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Relative file path"},
                },
                "required": ["path"],
            },
        ),
    ]


async def _guarded_call(
    tool_name: str,
    arguments: dict[str, Any],
) -> list[TextContent]:
    """Pass a tool call through AgentShield, then execute if allowed."""
    ctx = ToolCallContext(tool_name=tool_name, arguments=arguments)
    try:
        await shield.check(ctx)
    except ToolCallBlocked as exc:
        return [TextContent(type="text", text=f"BLOCKED: {exc.response.reason}")]

    # Simulate actual tool execution
    if tool_name == "execute_sql":
        return [
            TextContent(type="text", text=f"[result] Rows from: {arguments['query']}")
        ]
    if tool_name == "read_file":
        return [
            TextContent(type="text", text=f"[result] Contents of {arguments['path']}")
        ]
    return [TextContent(type="text", text="Unknown tool")]


@app.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    """Handle incoming tool calls with AgentShield protection."""
    return await _guarded_call(name, arguments)


async def main() -> None:
    """Run the MCP server over stdio."""
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
