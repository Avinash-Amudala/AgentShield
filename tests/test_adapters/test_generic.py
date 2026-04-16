from __future__ import annotations

import pytest

from agentshield import Shield, ToolCallBlocked
from agentshield.adapters.generic import protect_class_method, protect_function
from agentshield.core.result import PolicyAction
from agentshield.rules.sql_injection import DestructiveSQLRule


# ── protect_function ────────────────────────────────────────────────

class TestProtectFunction:
    async def test_protect_async_function_allows_safe(self):
        shield = Shield(rules=[DestructiveSQLRule()], mode="enforce")

        async def my_query(sql: str) -> str:
            return f"result: {sql}"

        protected = protect_function(my_query, shield, tool_name="my_query")
        result = await protected(sql="SELECT * FROM users")
        assert result == "result: SELECT * FROM users"

    async def test_protect_async_function_blocks_dangerous(self):
        shield = Shield(rules=[DestructiveSQLRule()], mode="enforce")

        async def my_query(sql: str) -> str:
            return f"result: {sql}"

        protected = protect_function(my_query, shield, tool_name="my_query")
        with pytest.raises(ToolCallBlocked):
            await protected(sql="DROP TABLE users")

    def test_protect_sync_function_allows_safe(self):
        shield = Shield(rules=[DestructiveSQLRule()], mode="enforce")

        def my_query(sql: str) -> str:
            return f"result: {sql}"

        protected = protect_function(my_query, shield)
        result = protected(sql="SELECT 1")
        assert result == "result: SELECT 1"

    def test_protect_sync_function_blocks_dangerous(self):
        shield = Shield(rules=[DestructiveSQLRule()], mode="enforce")

        def my_query(sql: str) -> str:
            return f"result: {sql}"

        protected = protect_function(my_query, shield)
        with pytest.raises(ToolCallBlocked):
            protected(sql="DROP TABLE users")

    async def test_protect_preserves_function_name(self):
        shield = Shield(rules=[], mode="enforce")

        async def original_func(x: int) -> int:
            return x * 2

        protected = protect_function(original_func, shield)
        assert protected.__name__ == "original_func"

    async def test_protect_custom_tool_name(self):
        shield = Shield(rules=[], mode="monitor")

        async def func(data: str) -> str:
            return data

        protected = protect_function(
            func, shield, tool_name="custom_name", agent_id="agent_007"
        )
        result = await protected(data="hello")
        assert result == "hello"


# ── protect_class_method ────────────────────────────────────────────

class TestProtectClassMethod:
    def test_protect_method_allows_safe(self):
        shield = Shield(rules=[DestructiveSQLRule()], mode="enforce")

        class DB:
            def query(self, sql: str) -> str:
                return f"result: {sql}"

        protect_class_method(DB, "query", shield)
        db = DB()
        result = db.query(sql="SELECT 1")
        assert result == "result: SELECT 1"

    def test_protect_method_blocks_dangerous(self):
        shield = Shield(rules=[DestructiveSQLRule()], mode="enforce")

        class DB:
            def query(self, sql: str) -> str:
                return f"result: {sql}"

        protect_class_method(DB, "query", shield)
        db = DB()
        with pytest.raises(ToolCallBlocked):
            db.query(sql="DROP TABLE users")

    def test_protect_method_uses_class_name(self):
        shield = Shield(rules=[], mode="enforce")

        class MyService:
            def do_work(self, task: str) -> str:
                return task

        protect_class_method(MyService, "do_work", shield)
        svc = MyService()
        result = svc.do_work(task="clean")
        assert result == "clean"

    def test_protect_method_custom_tool_name(self):
        shield = Shield(rules=[], mode="enforce")

        class MyService:
            def action(self, data: str) -> str:
                return data

        protect_class_method(
            MyService, "action", shield, tool_name="custom_action"
        )
        svc = MyService()
        result = svc.action(data="test")
        assert result == "test"

    def test_protect_nonexistent_method_raises(self):
        shield = Shield(rules=[], mode="enforce")

        class Empty:
            pass

        with pytest.raises(AttributeError):
            protect_class_method(Empty, "nonexistent", shield)

    async def test_protect_async_method(self):
        shield = Shield(rules=[DestructiveSQLRule()], mode="enforce")

        class AsyncDB:
            async def query(self, sql: str) -> str:
                return f"result: {sql}"

        protect_class_method(AsyncDB, "query", shield)
        db = AsyncDB()
        result = await db.query(sql="SELECT 1")
        assert result == "result: SELECT 1"
