"""
Shared building blocks and utilities used across the codebase.

This package contains cross-cutting helpers and integration adapters that are
reused by multiple modules/services.
"""

from .config import config
from .rehydrate import rehydrate_after_mcp_tool_call
from .logger import get_logger

__all__ = ["config", "rehydrate_after_mcp_tool_call", "get_logger"]