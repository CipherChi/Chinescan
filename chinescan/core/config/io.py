"""TOML configuration utilities."""

import os
import tomllib
from pathlib import Path

import tomli_w

from chinescan.core.config.settings import Settings, default_config_path
from chinescan.core.errors import ConfigurationError


def init_config(path: Path | None = None) -> Path:
    target = path or default_config_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        raise ConfigurationError(f"Configuration already exists: {target}")
    defaults = {"database_path": str(Settings().database_path), "log_level": "INFO"}
    target.write_text(tomli_w.dumps(defaults), encoding="utf-8")
    return target


def load_config(path: Path) -> Settings:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        for key in Settings.model_fields:
            env_name = f"CHINESCAN_{key.upper()}"
            if env_name in os.environ:
                data[key] = os.environ[env_name]
        return Settings(**data)
    except (OSError, ValueError) as exc:
        raise ConfigurationError(f"Unable to load configuration: {exc}") from exc


def validate_config(path: Path) -> Settings:
    if not path.exists():
        raise ConfigurationError(f"Configuration does not exist: {path}")
    return load_config(path)
