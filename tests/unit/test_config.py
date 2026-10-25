from pathlib import Path

import pytest

from chinescan.core.config.io import init_config, load_config, validate_config
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
