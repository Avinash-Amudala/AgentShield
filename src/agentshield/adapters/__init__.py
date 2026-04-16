"""Framework adapters for AgentShield.

Generic utilities are available directly; framework-specific adapters
(``mcp``, ``langchain``, ``crewai``, ``openai_sdk``) should be imported
from their respective sub-modules so that heavy dependencies stay lazy.
"""
from __future__ import annotations

from agentshield.adapters.generic import protect_class_method, protect_function

__all__ = ["protect_function", "protect_class_method"]
