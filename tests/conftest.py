from pathlib import Path

import pytest

from chinescan.core.storage.sqlite import SQLiteRepository


@pytest.fixture
def config_path(tmp_path: Path) -> Path:
    return tmp_path / "config.toml"


@pytest.fixture
def repository(tmp_path: Path) -> SQLiteRepository:
    repo = SQLiteRepository(tmp_path / "records.sqlite3")
    yield repo
    repo.close()
