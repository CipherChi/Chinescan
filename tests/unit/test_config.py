from pathlib import Path

import pytest

from chinescan.core.config import io as config_io
from chinescan.core.config.io import init_config, load_config, load_settings, validate_config
from chinescan.core.errors import ConfigurationError


def test_init_and_load_config(config_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    init_config(config_path)
    monkeypatch.setenv("CHINESCAN_LOG_LEVEL", "DEBUG")
    settings = load_config(config_path)
    assert settings.log_level == "DEBUG"
    assert "token" not in config_path.read_text(encoding="utf-8").lower()


def test_validate_missing_file(config_path: Path) -> None:
    with pytest.raises(ConfigurationError):
        validate_config(config_path)


def test_init_refuses_overwrite(config_path: Path) -> None:
    init_config(config_path)
    with pytest.raises(ConfigurationError):
        init_config(config_path)


def test_init_does_not_overwrite_file_created_after_existence_check(
    config_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_path.write_text("operator data", encoding="utf-8")
    monkeypatch.setattr(Path, "exists", lambda _: False)
    with pytest.raises(ConfigurationError, match="already exists"):
        init_config(config_path)
    assert config_path.read_text(encoding="utf-8") == "operator data"


def test_settings_precedence_is_cli_then_environment_then_file_then_defaults(
    config_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_path.write_text(
        'database_path = "file.sqlite3"\nlog_level = "WARNING"\n', encoding="utf-8"
    )
    monkeypatch.setenv("CHINESCAN_DATABASE_PATH", "environment.sqlite3")
    from_file_and_environment = load_settings(config_path)
    from_cli = load_settings(config_path, cli_overrides={"database_path": Path("cli.sqlite3")})

    assert from_file_and_environment.database_path == Path("environment.sqlite3")
    assert from_file_and_environment.log_level == "WARNING"
    assert from_cli.database_path == Path("cli.sqlite3")


def test_invalid_config_is_rejected_without_echoing_secret(config_path: Path) -> None:
    config_path.write_text('log_level = "TRACE"\napi_token = "fixture-secret"\n', encoding="utf-8")
    with pytest.raises(ConfigurationError) as exc_info:
        load_config(config_path)
    assert "fixture-secret" not in str(exc_info.value)


def test_environment_only_settings_use_defaults_when_config_is_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("CHINESCAN_DATABASE_PATH", raising=False)
    monkeypatch.delenv("CHINESCAN_CONFIG_PATH", raising=False)
    monkeypatch.setattr(config_io, "default_config_path", lambda: tmp_path / "missing.toml")
    settings = load_settings()
    assert settings.log_level == "INFO"
    assert settings.database_path != tmp_path / "missing.sqlite3"
