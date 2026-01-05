from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml


class ConfigError(RuntimeError):
    """Raised when configuration cannot be loaded."""


def _default_path() -> Path:
    # common/config.yaml next to this file
    return Path(__file__).resolve().with_name("config.yaml")


def _resolve_path(path: str | Path | None) -> Path:
    # Precedence:
    # 1) explicit argument
    # 2) env var override
    # 3) default next to this module
    env = os.getenv("COMMON_CONFIG_PATH")
    p = Path(path).expanduser() if path else (Path(env).expanduser() if env else _default_path())
    return p.resolve()


@lru_cache(maxsize=4)
def config(path: str | Path | None = None) -> dict[str, Any]:
    """
    Load config from YAML and return it as a dict.

    - Cached (fast to call from many modules)
    - Override location via `path=` or env var COMMON_CONFIG_PATH
    """
    p = _resolve_path(path)

    try:
        text = p.read_text(encoding="utf-8")
        cfg = yaml.safe_load(text)
        if not isinstance(cfg, dict):
            raise ValueError("YAML root must be a mapping/dict")
        return cfg
    except Exception as e:
        # single, clear message
        raise ConfigError(f"Failed to load config from {p}: {e}") from e


def reload_config() -> None:
    """Clear cached config (useful for tests)."""
    config.cache_clear()
