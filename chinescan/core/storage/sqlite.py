"""SQLAlchemy-backed SQLite repository."""

import json
from pathlib import Path
from typing import Any

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from sqlalchemy import JSON, Column, MetaData, String, Table, create_engine, inspect, select
from sqlalchemy.engine import Engine
from sqlalchemy.engine.reflection import Inspector

from chinescan.core.errors import StorageError
from chinescan.core.storage.repository import Repository

metadata = MetaData()
records = Table(
    "records",
    metadata,
    Column("record_type", String(80), primary_key=True),
    Column("record_id", String(255), primary_key=True),
    Column("payload", JSON, nullable=False),
)


class SQLiteRepository(Repository):
    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        url = f"sqlite:///{self.path.as_posix()}"
        self._migrate(url)
        self.engine: Engine = create_engine(url)

    def _migrate(self, url: str) -> None:
        """Upgrade fresh/known legacy stores; reject unknown schemas without altering them."""
        engine = create_engine(url)
        try:
            inspector = inspect(engine)
            tables = set(inspector.get_table_names()) - {"alembic_version"}
            with engine.connect() as connection:
                revision = MigrationContext.configure(connection).get_current_revision()
            if revision is None and tables:
                if tables != {"records"} or not self._is_initial_records_schema(inspector):
                    raise StorageError(
                        "SQLite schema is not a recognized ChineScan revision; "
                        "database left unchanged."
                    )
                config = self._alembic_config(url)
                command.stamp(config, "0001_initial")
                command.upgrade(config, "head")
            else:
                config = self._alembic_config(url)
                command.upgrade(config, "head")
        except StorageError:
            raise
        except Exception as exc:
            raise StorageError(
                "SQLite migration failed; database contents were not recreated."
            ) from exc
        finally:
            engine.dispose()

    @staticmethod
    def _is_initial_records_schema(inspector: Inspector) -> bool:
        columns = inspector.get_columns("records")
        primary_key = inspector.get_pk_constraint("records").get("constrained_columns", [])
        return [
            (column["name"], column["type"].__class__.__name__, column["nullable"])
            for column in columns
        ] == [
            ("record_type", "VARCHAR", False),
            ("record_id", "VARCHAR", False),
            ("payload", "JSON", False),
        ] and primary_key == ["record_type", "record_id"]

    @staticmethod
    def _alembic_config(url: str) -> Config:
        project_root = Path(__file__).resolve().parents[3]
        config = Config(str(project_root / "alembic.ini"))
        config.set_main_option("script_location", str(project_root / "migrations"))
        config.set_main_option("sqlalchemy.url", url)
        return config

    def save(self, record_type: str, record_id: str, payload: dict[str, Any]) -> None:
        with self.engine.begin() as connection:
            existing = connection.execute(
                select(records.c.record_id).where(
                    records.c.record_type == record_type, records.c.record_id == record_id
                )
            ).first()
            if existing:
                connection.execute(
                    records.update()
                    .where(records.c.record_type == record_type, records.c.record_id == record_id)
                    .values(payload=json.loads(json.dumps(payload)))
                )
            else:
                connection.execute(
                    records.insert().values(
                        record_type=record_type,
                        record_id=record_id,
                        payload=json.loads(json.dumps(payload)),
                    )
                )

    def get(self, record_type: str, record_id: str) -> dict[str, Any] | None:
        with self.engine.connect() as connection:
            row = connection.execute(
                select(records.c.payload).where(
                    records.c.record_type == record_type, records.c.record_id == record_id
                )
            ).first()
        return dict(row[0]) if row else None

    def list_records(self, record_type: str) -> list[dict[str, Any]]:
        """Return payloads for one record type from the local SQLite store."""
        with self.engine.connect() as connection:
            rows = connection.execute(
                select(records.c.payload).where(records.c.record_type == record_type)
            ).all()
        return [dict(row[0]) for row in rows]

    def close(self) -> None:
        self.engine.dispose()
