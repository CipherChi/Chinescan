"""Distinct, typed top-level investigation records."""

from datetime import datetime

from pydantic import Field

from chinescan.core.models.common import SchemaRecord


class Event(SchemaRecord):
    occurred_at: datetime
    kind: str
    summary: str


class Indicator(SchemaRecord):
    kind: str
    value: str
    confidence: float = Field(default=0.5, ge=0, le=1)


class Case(SchemaRecord):
    title: str
    description: str = ""
    status: str = "open"


class TimelineEntry(SchemaRecord):
    occurred_at: datetime
    description: str
    event_id: str | None = None


class Scan(SchemaRecord):
    target_id: str
    scanner: str
    started_at: datetime
    finished_at: datetime | None = None


class Target(SchemaRecord):
    value: str
    kind: str


class Artifact(SchemaRecord):
    name: str
    sha256: str | None = None
    media_type: str | None = None


class Report(SchemaRecord):
    title: str
    generated_at: datetime
    finding_ids: list[str] = Field(default_factory=list)


class Authorization(SchemaRecord):
    scope: list[str]
    granted_by: str
    valid_from: datetime
    valid_until: datetime | None = None
