"""SQLAlchemy-backed SQLite repository."""

import json
from pathlib import Path
from typing import Any

from sqlalchemy import JSON, Column, MetaData, String, Table, create_engine, select
from sqlalchemy.engine import Engine

from chinescan.core.storage.repository import Repository

metadata = MetaData()
records = Table(
    "records", metadata,
    Column("record_type", String(80), primary_key=True),
    Column("record_id", String(255), primary_key=True),
    Column("payload", JSON, nullable=False),
)


class SQLiteRepository(Repository):
    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.engine: Engine = create_engine(f"sqlite:///{self.path.as_posix()}")
        metadata.create_all(self.engine)

    def save(self, record_type: str, record_id: str, payload: dict[str, Any]) -> None:
        with self.engine.begin() as connection:
            existing = connection.execute(
                select(records.c.record_id).where(
                    records.c.record_type == record_type, records.c.record_id == record_id
                )
            ).first()
            if existing:
                connection.execute(records.update().where(
                    records.c.record_type == record_type, records.c.record_id == record_id
                ).values(payload=json.loads(json.dumps(payload))))
            else:
                connection.execute(records.insert().values(
                    record_type=record_type, record_id=record_id,
                    payload=json.loads(json.dumps(payload)),
                ))

    def get(self, record_type: str, record_id: str) -> dict[str, Any] | None:
        with self.engine.connect() as connection:
            row = connection.execute(select(records.c.payload).where(
                records.c.record_type == record_type, records.c.record_id == record_id
            )).first()
        return dict(row[0]) if row else None

    def close(self) -> None:
        self.engine.dispose()
