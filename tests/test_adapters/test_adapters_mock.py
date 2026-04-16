"""Tests for framework adapters using mocked imports."""

from __future__ import annotations

import asyncio
from types import ModuleType
from unittest import mock

import pytest

from agentshield import Shield, ToolCallBlocked
from agentshield.core.result import PolicyAction, PolicyResponse
from agentshield.rules.base import BaseRule


class AlwaysDeny(BaseRule):
    name = "deny_all"
    priority = 1

    async def evaluate(self, context):
        return PolicyResponse(
            action=PolicyAction.DENY, rule_name=self.name, reason="denied"
        )


def _make_agents_module():
    mod = ModuleType("agents")
    mod.Agent = type("Agent", (), {"tools": []})
    mod.FunctionTool = type("FunctionTool", (), {"fn": None, "name": "test"})
    return mod


def _make_langchain_modules():
    core_mod = ModuleType("langchain_core")
    tools_mod = ModuleType("langchain_core.tools")

    class BaseTool:
        name: str = ""
        description: str = ""

        def invoke(self, *a, **kw):
            return self._run(*a, **kw)

        def _run(self, *a, **kw):
            return ""

        async def _arun(self, *a, **kw):
            return ""

    class ToolException(Exception):
        pass

    tools_mod.BaseTool = BaseTool
    tools_mod.ToolException = ToolException
    core_mod.tools = tools_mod
    return {"langchain_core": core_mod, "langchain_core.tools": tools_mod}


def _make_crewai_modules():
    crewai_mod = ModuleType("crewai")
    tools_mod = ModuleType("crewai.tools")

    class BaseTool:
        name: str = ""
        description: str = ""

        def _run(self, *a, **kw):
            return ""

    class Crew:
        agents = []

        def __init__(self, **kw):
            self.agents = kw.get("agents", [])

    tools_mod.BaseTool = BaseTool
    crewai_mod.Crew = Crew
    crewai_mod.tools = tools_mod
    return {"crewai": crewai_mod, "crewai.tools": tools_mod}


def _make_mcp_modules():
    mcp_mod = ModuleType("mcp")
    server_mod = ModuleType("mcp.server")

    class Server:
        def __init__(self):
            self._tool_handlers = {}

    server_mod.Server = Server
    mcp_mod.server = server_mod
    return {"mcp": mcp_mod, "mcp.server": server_mod}


class TestOpenAIAdapter:
    def test_shield_agent_async_tool(self):
        agents_mod = _make_agents_module()
        with mock.patch.dict("sys.modules", {"agents": agents_mod}):
            from agentshield.adapters.openai_sdk import (
                shield_agent,
                _ensure_openai_agents,
            )

            Agent, FunctionTool = _ensure_openai_agents()

            async def my_fn(query: str = "") -> str:
                return query

            tool = FunctionTool()
            tool.fn = my_fn
            tool.name = "execute_sql"

            agent = Agent()
            agent.tools = [tool]

            shield = Shield(rules=[], mode="enforce")
            shield_agent(agent, shield, agent_id="test")
            assert agent.tools[0].fn is not my_fn

            result = asyncio.run(agent.tools[0].fn(query="hello"))
            assert result == "hello"

    def test_shield_agent_sync_tool(self):
        agents_mod = _make_agents_module()
        with mock.patch.dict("sys.modules", {"agents": agents_mod}):
            from agentshield.adapters.openai_sdk import shield_agent

            Agent, FunctionTool = agents_mod.Agent, agents_mod.FunctionTool

            def my_fn(query: str = "") -> str:
                return query

            tool = FunctionTool()
            tool.fn = my_fn
            tool.name = "safe_tool"

            agent = Agent()
            agent.tools = [tool]

            shield = Shield(rules=[], mode="enforce")
            shield_agent(agent, shield)
            result = agent.tools[0].fn(query="test")
            assert result == "test"

    def test_shield_agent_sync_tool_denied(self):
        agents_mod = _make_agents_module()
        with mock.patch.dict("sys.modules", {"agents": agents_mod}):
            from agentshield.adapters.openai_sdk import shield_agent

            Agent, FunctionTool = agents_mod.Agent, agents_mod.FunctionTool

            def my_fn(query: str = "") -> str:
                return query

            tool = FunctionTool()
            tool.fn = my_fn
            tool.name = "blocked"

            agent = Agent()
            agent.tools = [tool]

            shield = Shield(rules=[AlwaysDeny()], mode="enforce")
            shield_agent(agent, shield)
            with pytest.raises(ToolCallBlocked):
                agent.tools[0].fn(query="test")

    def test_shield_agent_async_tool_denied(self):
        agents_mod = _make_agents_module()
        with mock.patch.dict("sys.modules", {"agents": agents_mod}):
            from agentshield.adapters.openai_sdk import shield_agent

            Agent, FunctionTool = agents_mod.Agent, agents_mod.FunctionTool

            async def my_fn(query: str = "") -> str:
                return query

            tool = FunctionTool()
            tool.fn = my_fn
            tool.name = "blocked"

            agent = Agent()
            agent.tools = [tool]

            shield = Shield(rules=[AlwaysDeny()], mode="enforce")
            shield_agent(agent, shield)
            with pytest.raises(ToolCallBlocked):
                asyncio.run(agent.tools[0].fn(query="test"))

    def test_shield_agent_wrong_type(self):
        agents_mod = _make_agents_module()
        with mock.patch.dict("sys.modules", {"agents": agents_mod}):
            from agentshield.adapters.openai_sdk import shield_agent

            shield = Shield(rules=[], mode="enforce")
            with pytest.raises(TypeError, match="Expected an agents.Agent"):
                shield_agent("not an agent", shield)

    def test_shielded_function_tool_async(self):
        agents_mod = _make_agents_module()
        with mock.patch.dict("sys.modules", {"agents": agents_mod}):
            from agentshield.adapters.openai_sdk import shielded_function_tool

            shield = Shield(rules=[], mode="enforce")

            @shielded_function_tool(shield, tool_name="my_tool")
            async def my_func(x: int = 0) -> int:
                return x + 1

            result = asyncio.run(my_func(x=5))
            assert result == 6

    def test_shielded_function_tool_sync(self):
        agents_mod = _make_agents_module()
        with mock.patch.dict("sys.modules", {"agents": agents_mod}):
            from agentshield.adapters.openai_sdk import shielded_function_tool

            shield = Shield(rules=[], mode="enforce")

            @shielded_function_tool(shield, tool_name="sync_tool")
            def my_func(x: int = 0) -> int:
                return x + 1

            assert my_func(x=10) == 11

    def test_shielded_function_tool_async_denied(self):
        agents_mod = _make_agents_module()
        with mock.patch.dict("sys.modules", {"agents": agents_mod}):
            from agentshield.adapters.openai_sdk import shielded_function_tool

            shield = Shield(rules=[AlwaysDeny()], mode="enforce")

            @shielded_function_tool(shield)
            async def my_func(x: int = 0) -> int:
                return x

            with pytest.raises(ToolCallBlocked):
                asyncio.run(my_func(x=1))


class TestLangChainAdapter:
    def test_shielded_toolkit(self):
        mods = _make_langchain_modules()
        with mock.patch.dict("sys.modules", mods):
            from agentshield.adapters.langchain import ShieldedToolkit

            BaseTool = mods["langchain_core.tools"].BaseTool

            class MyTool(BaseTool):
                name = "execute_sql"
                description = "run sql"

                def _run(self, query: str = "", **kw):
                    return f"result: {query}"

                async def _arun(self, query: str = "", **kw):
                    return f"result: {query}"

            shield = Shield(rules=[], mode="enforce")
            toolkit = ShieldedToolkit([MyTool()], shield=shield)
            tools = toolkit.tools()
            assert len(tools) == 1

            result = tools[0]._run(query="SELECT 1")
            assert "result:" in result

    def test_shielded_toolkit_run_blocked(self):
        mods = _make_langchain_modules()
        with mock.patch.dict("sys.modules", mods):
            from agentshield.adapters.langchain import ShieldedToolkit

            BaseTool = mods["langchain_core.tools"].BaseTool

            class MyTool(BaseTool):
                name = "rm_rf"
                description = "dangerous"

                def _run(self, **kw):
                    return "done"

                async def _arun(self, **kw):
                    return "done"

            shield = Shield(rules=[AlwaysDeny()], mode="enforce")
            toolkit = ShieldedToolkit([MyTool()], shield=shield)
            result = toolkit.tools()[0]._run()
            assert "blocked" in result.lower()

    def test_shielded_toolkit_arun(self):
        mods = _make_langchain_modules()
        with mock.patch.dict("sys.modules", mods):
            from agentshield.adapters.langchain import ShieldedToolkit

            BaseTool = mods["langchain_core.tools"].BaseTool

            class MyTool(BaseTool):
                name = "search"
                description = "search"

                def _run(self, **kw):
                    return "sync"

                async def _arun(self, **kw):
                    return "async"

            shield = Shield(rules=[], mode="enforce")
            toolkit = ShieldedToolkit([MyTool()], shield=shield)
            result = asyncio.run(toolkit.tools()[0]._arun())
            assert result == "async"

    def test_shielded_toolkit_arun_blocked(self):
        mods = _make_langchain_modules()
        with mock.patch.dict("sys.modules", mods):
            from agentshield.adapters.langchain import ShieldedToolkit

            BaseTool = mods["langchain_core.tools"].BaseTool

            class MyTool(BaseTool):
                name = "rm"
                description = "rm"

                def _run(self, **kw):
                    return ""

                async def _arun(self, **kw):
                    return ""

            shield = Shield(rules=[AlwaysDeny()], mode="enforce")
            toolkit = ShieldedToolkit([MyTool()], shield=shield)
            result = asyncio.run(toolkit.tools()[0]._arun())
            assert "blocked" in result.lower()


class TestCrewAIAdapter:
    def test_shield_crew(self):
        mods = _make_crewai_modules()
        with mock.patch.dict("sys.modules", mods):
            from agentshield.adapters.crewai import shield_crew

            Crew = mods["crewai"].Crew
            BaseTool = mods["crewai.tools"].BaseTool

            class MyTool(BaseTool):
                name = "db"
                description = "query db"

                def _run(self, query="", **kw):
                    return query

            crew = Crew()
            agent = mock.MagicMock()
            agent.tools = [MyTool()]
            crew.agents = [agent]

            shield = Shield(rules=[], mode="enforce")
            shield_crew(crew, shield=shield)
            result = agent.tools[0]._run(query="SELECT 1")
            assert result == "SELECT 1"

    def test_shield_crew_blocked(self):
        mods = _make_crewai_modules()
        with mock.patch.dict("sys.modules", mods):
            from agentshield.adapters.crewai import shield_crew

            Crew = mods["crewai"].Crew
            BaseTool = mods["crewai.tools"].BaseTool

            class MyTool(BaseTool):
                name = "danger"

                def _run(self, **kw):
                    return "done"

            crew = Crew()
            agent = mock.MagicMock()
            agent.tools = [MyTool()]
            crew.agents = [agent]

            shield = Shield(rules=[AlwaysDeny()], mode="enforce")
            shield_crew(crew, shield=shield)
            result = agent.tools[0]._run()
            assert "blocked" in result.lower()

    def test_shield_crew_wrong_type(self):
        mods = _make_crewai_modules()
        with mock.patch.dict("sys.modules", mods):
            from agentshield.adapters.crewai import shield_crew

            shield = Shield(rules=[], mode="enforce")
            with pytest.raises(TypeError, match="crewai.Crew"):
                shield_crew("not a crew", shield=shield)

    def test_shield_tool_decorator(self):
        mods = _make_crewai_modules()
        with mock.patch.dict("sys.modules", mods):
            from agentshield.adapters.crewai import shield_tool

            shield = Shield(rules=[], mode="enforce")

            @shield_tool(shield, tool_name="my_tool")
            def search(query: str = "") -> str:
                return f"found: {query}"

            assert search(query="test") == "found: test"

    def test_shield_tool_decorator_blocked(self):
        mods = _make_crewai_modules()
        with mock.patch.dict("sys.modules", mods):
            from agentshield.adapters.crewai import shield_tool

            shield = Shield(rules=[AlwaysDeny()], mode="enforce")

            @shield_tool(shield)
            def search(query: str = "") -> str:
                return query

            result = search(query="x")
            assert "blocked" in result.lower()


class TestMCPAdapter:
    def test_shield_mcp_server(self):
        mods = _make_mcp_modules()
        with mock.patch.dict("sys.modules", mods):
            from agentshield.adapters.mcp import shield_mcp_server

            Server = mods["mcp.server"].Server
            server = Server()

            async def my_handler(**kw):
                return f"ok: {kw}"

            server._tool_handlers["my_tool"] = my_handler

            shield = Shield(rules=[], mode="enforce")
            shield_mcp_server(server, shield)
            result = asyncio.run(server._tool_handlers["my_tool"](arg="val"))
            assert "ok" in result

    def test_shield_mcp_server_blocked(self):
        mods = _make_mcp_modules()
        with mock.patch.dict("sys.modules", mods):
            from agentshield.adapters.mcp import shield_mcp_server

            Server = mods["mcp.server"].Server
            server = Server()

            async def my_handler(**kw):
                return "done"

            server._tool_handlers["danger"] = my_handler
            shield = Shield(rules=[AlwaysDeny()], mode="enforce")
            shield_mcp_server(server, shield)
            with pytest.raises(ToolCallBlocked):
                asyncio.run(server._tool_handlers["danger"]())

    def test_shield_mcp_wrong_type(self):
        mods = _make_mcp_modules()
        with mock.patch.dict("sys.modules", mods):
            from agentshield.adapters.mcp import shield_mcp_server

            shield = Shield(rules=[], mode="enforce")
            with pytest.raises(TypeError, match="mcp.server.Server"):
                shield_mcp_server("not a server", shield)

    def test_shielded_tool_decorator(self):
        mods = _make_mcp_modules()
        with mock.patch.dict("sys.modules", mods):
            from agentshield.adapters.mcp import shielded_tool

            shield = Shield(rules=[], mode="enforce")

            @shielded_tool(shield, tool_name="read_file")
            async def read_file(path: str = "") -> str:
                return f"content of {path}"

            result = asyncio.run(read_file(path="/tmp/f.txt"))
            assert "content of" in result

    def test_shielded_tool_decorator_blocked(self):
        mods = _make_mcp_modules()
        with mock.patch.dict("sys.modules", mods):
            from agentshield.adapters.mcp import shielded_tool

            shield = Shield(rules=[AlwaysDeny()], mode="enforce")

            @shielded_tool(shield)
            async def read_file(path: str = "") -> str:
                return ""

            with pytest.raises(ToolCallBlocked):
                asyncio.run(read_file(path="/etc/passwd"))
