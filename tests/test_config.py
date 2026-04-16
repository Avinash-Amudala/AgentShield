"""Tests for the configuration loading module."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentshield.core.config import (
    ShieldConfig,
    _apply_env_overrides,
    _find_config_file,
    _load_yaml,
    load_config,
)


class TestShieldConfig:
    def test_defaults(self):
        cfg = ShieldConfig()
        assert cfg.mode == "enforce"
        assert cfg.default_action == "allow"
        assert cfg.dashboard_port is None

    def test_invalid_mode(self):
        with pytest.raises(ValueError, match="Invalid mode"):
            ShieldConfig(mode="turbo")

    def test_invalid_action(self):
        with pytest.raises(ValueError, match="Invalid default_action"):
            ShieldConfig(default_action="nuke")

    def test_dashboard_port_coerced(self):
        cfg = ShieldConfig(dashboard_port="8080")
        assert cfg.dashboard_port == 8080

    def test_all_modes(self):
        for mode in ("enforce", "monitor", "dry-run"):
            cfg = ShieldConfig(mode=mode)
            assert cfg.mode == mode


class TestLoadYaml:
    def test_load(self, tmp_path: Path):
        f = tmp_path / "cfg.yaml"
        f.write_text("mode: monitor\nlog_file: test.jsonl\n", encoding="utf-8")
        data = _load_yaml(f)
        assert data["mode"] == "monitor"

    def test_empty_yaml(self, tmp_path: Path):
        f = tmp_path / "empty.yaml"
        f.write_text("", encoding="utf-8")
        assert _load_yaml(f) == {}


class TestApplyEnvOverrides:
    def test_applies_env(self, monkeypatch):
        monkeypatch.setenv("AGENTSHIELD_MODE", "monitor")
        monkeypatch.setenv("AGENTSHIELD_LOG_FILE", "/tmp/test.jsonl")
        data: dict = {}
        _apply_env_overrides(data)
        assert data["mode"] == "monitor"
        assert data["log_file"] == "/tmp/test.jsonl"

    def test_no_env(self):
        data: dict = {"mode": "enforce"}
        result = _apply_env_overrides(data)
        assert result["mode"] == "enforce"


class TestFindConfigFile:
    def test_no_file(self, tmp_path: Path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        assert _find_config_file() is None

    def test_finds_cwd_config(self, tmp_path: Path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        cfg = tmp_path / "agentshield.yaml"
        cfg.write_text("mode: monitor\n", encoding="utf-8")
        assert _find_config_file() == cfg


class TestLoadConfig:
    def test_defaults(self, tmp_path: Path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        for k in (
            "AGENTSHIELD_MODE",
            "AGENTSHIELD_LOG_FILE",
            "AGENTSHIELD_DEFAULT_ACTION",
            "AGENTSHIELD_DASHBOARD_PORT",
        ):
            monkeypatch.delenv(k, raising=False)
        cfg = load_config()
        assert cfg.mode == "enforce"

    def test_explicit_path(self, tmp_path: Path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        for k in (
            "AGENTSHIELD_MODE",
            "AGENTSHIELD_LOG_FILE",
            "AGENTSHIELD_DEFAULT_ACTION",
            "AGENTSHIELD_DASHBOARD_PORT",
        ):
            monkeypatch.delenv(k, raising=False)
        f = tmp_path / "custom.yaml"
        f.write_text("mode: dry-run\n", encoding="utf-8")
        cfg = load_config(config_path=str(f))
        assert cfg.mode == "dry-run"

    def test_missing_explicit_raises(self, tmp_path: Path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        with pytest.raises(FileNotFoundError):
            load_config(config_path="/no/such/file.yaml")

    def test_env_overrides_yaml(self, tmp_path: Path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        for k in (
            "AGENTSHIELD_LOG_FILE",
            "AGENTSHIELD_DEFAULT_ACTION",
            "AGENTSHIELD_DASHBOARD_PORT",
        ):
            monkeypatch.delenv(k, raising=False)
        f = tmp_path / "agentshield.yaml"
        f.write_text("mode: enforce\n", encoding="utf-8")
        monkeypatch.setenv("AGENTSHIELD_MODE", "monitor")
        cfg = load_config()
        assert cfg.mode == "monitor"

    def test_unknown_fields_ignored(self, tmp_path: Path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        for k in (
            "AGENTSHIELD_MODE",
            "AGENTSHIELD_LOG_FILE",
            "AGENTSHIELD_DEFAULT_ACTION",
            "AGENTSHIELD_DASHBOARD_PORT",
        ):
            monkeypatch.delenv(k, raising=False)
        f = tmp_path / "agentshield.yaml"
        f.write_text("mode: enforce\nfoo: bar\n", encoding="utf-8")
        cfg = load_config()
        assert not hasattr(cfg, "foo")
