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
