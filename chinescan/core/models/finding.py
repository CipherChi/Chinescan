"""Finding and external reference records."""

from uuid import uuid4

from pydantic import Field, HttpUrl

from chinescan.core.models.common import Confidence, FindingCategory, SchemaRecord, Severity


class Reference(SchemaRecord):
    title: str
    url: HttpUrl | None = None


class Finding(SchemaRecord):
    finding_id: str = Field(default_factory=lambda: str(uuid4()))
    title: str
    description: str = ""
    severity: Severity = Severity.INFO
    fingerprint: str = Field(min_length=1)
    category: FindingCategory = FindingCategory.SAST
    confidence: Confidence = Confidence.POSSIBLE
    scanner: str = "unknown"
    rule_id: str = "unknown"
    location: str | None = None
    references: list[Reference] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
