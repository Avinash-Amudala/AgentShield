from __future__ import annotations

import json


from agentshield.audit.logger import AuditLogger
from agentshield.audit.verifier import AuditVerifier
from agentshield.core.context import ToolCallContext
from agentshield.core.result import PolicyAction, PolicyResponse


def _make_ctx(tool_name: str = "test_tool", **kwargs) -> ToolCallContext:
    return ToolCallContext(
        tool_name=tool_name,
        arguments=kwargs,
        session_id="test-session",
        agent_id="test-agent",
    )


def _make_response(
    action: PolicyAction = PolicyAction.ALLOW,
    rule_name: str = "test_rule",
    reason: str = "test reason",
) -> PolicyResponse:
    return PolicyResponse(action=action, rule_name=rule_name, reason=reason)


# ── AuditLogger ─────────────────────────────────────────────────────


class TestAuditLoggerEntryCreation:
    async def test_log_creates_entry_with_required_fields(self, tmp_path):
        log_file = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_file=log_file)
        ctx = _make_ctx(query="SELECT 1")
        resp = _make_response()

        entry = await logger.log(ctx, resp)

        assert "id" in entry
        assert "timestamp" in entry
        assert entry["tool_name"] == "test_tool"
        assert entry["agent_id"] == "test-agent"
        assert entry["session_id"] == "test-session"
        assert entry["action"] == "allow"
        assert entry["rule_name"] == "test_rule"
        assert entry["reason"] == "test reason"

    async def test_log_hashes_arguments(self, tmp_path):
        log_file = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_file=log_file)
        ctx = _make_ctx(secret="my-api-key")
        resp = _make_response()

        entry = await logger.log(ctx, resp)

        assert entry["arguments_hash"].startswith("sha256:")
        assert "my-api-key" not in json.dumps(entry)

    async def test_log_writes_to_file(self, tmp_path):
        log_file = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_file=log_file)
        ctx = _make_ctx()
        resp = _make_response()

        await logger.log(ctx, resp)

        content = log_file.read_text(encoding="utf-8")
        lines = [line for line in content.strip().split("\n") if line.strip()]
        assert len(lines) == 1
        parsed = json.loads(lines[0])
        assert parsed["tool_name"] == "test_tool"


class TestAuditLoggerHashChain:
    async def test_first_entry_chains_from_genesis(self, tmp_path):
        log_file = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_file=log_file)
        ctx = _make_ctx()
        resp = _make_response()

        entry = await logger.log(ctx, resp)

        assert entry["prev_hash"] == "genesis"

    async def test_second_entry_chains_from_first(self, tmp_path):
        log_file = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_file=log_file)
        ctx = _make_ctx()
        resp = _make_response()

        entry1 = await logger.log(ctx, resp)
        entry2 = await logger.log(ctx, resp)

        assert entry2["prev_hash"] == entry1["entry_hash"]

    async def test_entry_hash_is_deterministic(self, tmp_path):
        log_file = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_file=log_file)
        ctx = _make_ctx()
        resp = _make_response()

        entry = await logger.log(ctx, resp)
        assert entry["entry_hash"].startswith("sha256:")
        assert len(entry["entry_hash"]) > 10

    async def test_multiple_entries_form_chain(self, tmp_path):
        log_file = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_file=log_file)
        ctx = _make_ctx()
        resp = _make_response()

        entries = []
        for _ in range(5):
            entries.append(await logger.log(ctx, resp))

        for i in range(1, len(entries)):
            assert entries[i]["prev_hash"] == entries[i - 1]["entry_hash"]


class TestAuditLoggerResume:
    async def test_resume_chain_from_existing_log(self, tmp_path):
        log_file = tmp_path / "audit.jsonl"
        logger1 = AuditLogger(log_file=log_file)
        ctx = _make_ctx()
        resp = _make_response()

        entry1 = await logger1.log(ctx, resp)

        logger2 = AuditLogger(log_file=log_file)
        entry2 = await logger2.log(ctx, resp)

        assert entry2["prev_hash"] == entry1["entry_hash"]


# ── AuditVerifier ───────────────────────────────────────────────────


class TestAuditVerifierValid:
    async def test_verify_valid_single_entry(self, tmp_path):
        log_file = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_file=log_file)
        await logger.log(_make_ctx(), _make_response())

        verifier = AuditVerifier()
        result = verifier.verify(log_file)

        assert result.valid is True
        assert result.total_entries == 1
        assert result.broken_links == []

    async def test_verify_valid_chain_multiple_entries(self, tmp_path):
        log_file = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_file=log_file)
        for i in range(10):
            await logger.log(
                _make_ctx(tool_name=f"tool_{i}"),
                _make_response(rule_name=f"rule_{i}"),
            )

        verifier = AuditVerifier()
        result = verifier.verify(log_file)

        assert result.valid is True
        assert result.total_entries == 10

    def test_verify_empty_file(self, tmp_path):
        log_file = tmp_path / "audit.jsonl"
        log_file.write_text("")

        verifier = AuditVerifier()
        result = verifier.verify(log_file)

        assert result.valid is True
        assert result.total_entries == 0

    def test_verify_nonexistent_file(self, tmp_path):
        log_file = tmp_path / "does_not_exist.jsonl"

        verifier = AuditVerifier()
        result = verifier.verify(log_file)

        assert result.valid is True
        assert result.total_entries == 0


class TestAuditVerifierTamperDetection:
    async def test_detect_modified_reason(self, tmp_path):
        log_file = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_file=log_file)
        await logger.log(_make_ctx(), _make_response())

        lines = log_file.read_text(encoding="utf-8").strip().split("\n")
        entry = json.loads(lines[0])
        entry["reason"] = "tampered reason"
        lines[0] = json.dumps(entry, separators=(",", ":"))
        log_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

        verifier = AuditVerifier()
        result = verifier.verify(log_file)

        assert result.valid is False
        assert len(result.broken_links) > 0

    async def test_detect_deleted_entry(self, tmp_path):
        log_file = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_file=log_file)
        for _ in range(3):
            await logger.log(_make_ctx(), _make_response())

        lines = log_file.read_text(encoding="utf-8").strip().split("\n")
        del lines[1]  # remove second entry
        log_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

        verifier = AuditVerifier()
        result = verifier.verify(log_file)

        assert result.valid is False

    async def test_detect_modified_action(self, tmp_path):
        log_file = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_file=log_file)
        await logger.log(
            _make_ctx(),
            _make_response(action=PolicyAction.DENY, reason="blocked"),
        )

        lines = log_file.read_text(encoding="utf-8").strip().split("\n")
        entry = json.loads(lines[0])
        entry["action"] = "allow"
        lines[0] = json.dumps(entry, separators=(",", ":"))
        log_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

        verifier = AuditVerifier()
        result = verifier.verify(log_file)

        assert result.valid is False

    async def test_broken_link_has_line_info(self, tmp_path):
        log_file = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_file=log_file)
        await logger.log(_make_ctx(), _make_response())

        lines = log_file.read_text(encoding="utf-8").strip().split("\n")
        entry = json.loads(lines[0])
        entry["tool_name"] = "hacked"
        lines[0] = json.dumps(entry, separators=(",", ":"))
        log_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

        verifier = AuditVerifier()
        result = verifier.verify(log_file)

        assert len(result.broken_links) >= 1
        link = result.broken_links[0]
        assert link.line_number == 1
        assert link.entry_id == entry["id"]


class TestAuditLoggerSyncInterface:
    def test_log_sync_creates_entry(self, tmp_path):
        log_file = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_file=log_file)
        ctx = _make_ctx()
        resp = _make_response()

        entry = logger.log_sync(ctx, resp)

        assert "id" in entry
        assert entry["tool_name"] == "test_tool"

        content = log_file.read_text(encoding="utf-8")
        assert len(content.strip().split("\n")) == 1
