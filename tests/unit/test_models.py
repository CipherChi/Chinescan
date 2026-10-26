import pytest
from pydantic import ValidationError

from chinescan.core.models import Confidence, Finding, FindingCategory, Severity, Target


def test_finding_is_versioned_and_serializable() -> None:
    finding = Finding(title="Weak setting", fingerprint="abc", severity=Severity.HIGH)
    assert finding.schema_version == "1.0"
    assert finding.model_dump(mode="json")["severity"] == "high"
    assert finding.model_dump(mode="json")["category"] == FindingCategory.SAST.value
    assert finding.model_dump(mode="json")["confidence"] == Confidence.POSSIBLE.value


def test_finding_requires_fingerprint() -> None:
    with pytest.raises(ValidationError):
        Finding(title="Missing fingerprint")


def test_target_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        Target(value="host", kind="hostname", extra_field=True)
