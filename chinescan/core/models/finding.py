"""Finding and external reference records."""

from pydantic import Field, HttpUrl

from chinescan.core.models.common import SchemaRecord, Severity


class Reference(SchemaRecord):
    title: str
    url: HttpUrl | None = None


class Finding(SchemaRecord):
    title: str
    description: str = ""
    severity: Severity = Severity.INFO
    fingerprint: str = Field(min_length=1)
    references: list[Reference] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
