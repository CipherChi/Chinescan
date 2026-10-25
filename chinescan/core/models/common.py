"""Shared model fields and enums."""

from enum import StrEnum

from pydantic import BaseModel, ConfigDict


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SchemaRecord(BaseModel):
    """Base for versioned JSON-compatible records."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    schema_version: str = "1.0"
