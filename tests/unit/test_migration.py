from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect


def test_initial_migration_creates_records_table(tmp_path: Path) -> None:
    database = tmp_path / "migration.sqlite3"
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite:///{database.as_posix()}")
    command.upgrade(config, "head")
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    try:
        assert "records" in inspect(engine).get_table_names()
    finally:
        engine.dispose()
