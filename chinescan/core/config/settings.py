"""Typed application settings and CHINESCAN_ environment overrides."""

from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


def default_config_path() -> Path:
    return Path.home() / ".config" / "chinescan" / "config.toml"


def default_data_path() -> Path:
    return Path.home() / ".local" / "share" / "chinescan" / "chinescan.sqlite3"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="CHINESCAN_", extra="ignore")
    database_path: Path = Field(default_factory=default_data_path)
    malware_managed_directory: Path | None = None
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    api_token: str | None = Field(default=None, repr=False)
