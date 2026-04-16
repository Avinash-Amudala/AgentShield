"""Configuration loading for AgentShield."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger("agentshield.config")

_MODES = frozenset({"enforce", "monitor", "dry-run"})
_ACTIONS = frozenset({"allow", "deny", "escalate"})

_ENV_MAP: dict[str, str] = {
    "AGENTSHIELD_MODE": "mode",
    "AGENTSHIELD_LOG_FILE": "log_file",
    "AGENTSHIELD_DEFAULT_ACTION": "default_action",
    "AGENTSHIELD_DASHBOARD_PORT": "dashboard_port",
}


@dataclass
class ShieldConfig:
    """Top-level configuration for an AgentShield instance.

    Attributes:
        mode: Operating mode — ``"enforce"``, ``"monitor"``, or ``"dry-run"``.
        log_file: Path to the JSONL audit log.
        default_action: Fallback action when no rule matches.
        dashboard_port: Port for the live dashboard, or *None* to disable.
        rules: Per-rule configuration keyed by rule name.
        custom_rules: List of inline custom-rule definitions.
        hitl: HITL (Human-in-the-Loop) gateway settings.
    """

    mode: str = "enforce"
    log_file: str = "./shield.jsonl"
    default_action: str = "allow"
    dashboard_port: int | None = None
    rules: dict[str, dict[str, Any]] = field(default_factory=dict)
    custom_rules: list[dict[str, Any]] = field(default_factory=list)
    hitl: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.mode not in _MODES:
            raise ValueError(
                f"Invalid mode {self.mode!r}. Must be one of {sorted(_MODES)}."
            )
        if self.default_action not in _ACTIONS:
            raise ValueError(
                f"Invalid default_action {self.default_action!r}. "
                f"Must be one of {sorted(_ACTIONS)}."
            )
        if self.dashboard_port is not None:
            self.dashboard_port = int(self.dashboard_port)


def _load_yaml(path: Path) -> dict[str, Any]:
    """Parse a YAML file, raising a helpful error when PyYAML is absent.

    Args:
        path: Filesystem path to the YAML file.

    Returns:
        Parsed YAML content as a dictionary.

    Raises:
        ImportError: When PyYAML is not installed.
        FileNotFoundError: When *path* does not exist.
    """
    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError:
        raise ImportError(
            f"PyYAML is required to load {path}. Install it with: " "pip install pyyaml"
        ) from None

    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    return data if isinstance(data, dict) else {}


def _find_config_file() -> Path | None:
    """Search the default config locations.

    Order:
        1. ``./agentshield.yaml`` (current working directory)
        2. ``~/.agentshield/config.yaml`` (user home)

    Returns:
        The first path that exists, or *None*.
    """
    candidates = [
        Path.cwd() / "agentshield.yaml",
        Path.home() / ".agentshield" / "config.yaml",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def _apply_env_overrides(data: dict[str, Any]) -> dict[str, Any]:
    """Layer environment-variable overrides onto *data*.

    Args:
        data: Mutable config dict to update in place.

    Returns:
        The same dict, mutated for convenience.
    """
    for env_var, key in _ENV_MAP.items():
        value = os.environ.get(env_var)
        if value is not None:
            data[key] = value
    return data


def load_config(config_path: str | Path | None = None) -> ShieldConfig:
    """Load configuration with cascading priority.

    Resolution order (later wins):
        1. Auto-discovered YAML file (CWD then ``~/.agentshield/``)
        2. Explicitly provided *config_path*
        3. Environment variables (``AGENTSHIELD_*``)

    When no YAML file is found and no *config_path* is given, a default
    :class:`ShieldConfig` is returned (with env-var overrides applied).

    Args:
        config_path: Optional explicit path to a YAML config file.

    Returns:
        A fully resolved :class:`ShieldConfig`.

    Raises:
        FileNotFoundError: If *config_path* is given but does not exist.
        ImportError: If a YAML file is found but PyYAML is not installed.
    """
    data: dict[str, Any] = {}

    # --- 1. Auto-discover config file ---
    discovered = _find_config_file()
    if discovered is not None:
        logger.debug("Auto-discovered config: %s", discovered)
        data.update(_load_yaml(discovered))

    # --- 2. Explicit config path (overrides auto-discovered) ---
    if config_path is not None:
        explicit = Path(config_path)
        if not explicit.is_file():
            raise FileNotFoundError(f"Config file not found: {explicit}")
        logger.debug("Loading explicit config: %s", explicit)
        data.update(_load_yaml(explicit))

    # --- 3. Environment variables (highest priority) ---
    _apply_env_overrides(data)

    # Build the dataclass, extracting only known fields.
    known_fields = {f.name for f in ShieldConfig.__dataclass_fields__.values()}
    filtered = {k: v for k, v in data.items() if k in known_fields}

    return ShieldConfig(**filtered)
