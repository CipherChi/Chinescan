"""Shared model fields and enums."""

from enum import StrEnum

from pydantic import BaseModel, ConfigDict


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingCategory(StrEnum):
    SAST = "SAST"
    SCA = "SCA"
    SECRETS = "SECRETS"
    IAC = "IAC"
    CONTAINER = "CONTAINER"
    NETWORK = "NETWORK"
    WEB = "WEB"
    TLS = "TLS"
    DNS = "DNS"
    LOG = "LOG"
    MALWARE = "MALWARE"
    MEMORY = "MEMORY"
    THREAT_INTEL = "THREAT_INTEL"


class Confidence(StrEnum):
    CONFIRMED = "CONFIRMED"
    LIKELY = "LIKELY"
    POSSIBLE = "POSSIBLE"
    INFORMATIONAL = "INFORMATIONAL"


class SchemaRecord(BaseModel):
    """Base for versioned JSON-compatible records."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    schema_version: str = "1.0"
