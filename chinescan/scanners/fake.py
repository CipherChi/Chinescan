"""Deterministic in-memory adapter used by tests and examples."""

from chinescan.core.models.finding import Finding
from chinescan.core.models.investigation import Target


class FakeScanner:
    name = "fake"

    def __init__(self, findings: list[Finding] | None = None) -> None:
        self.findings = findings or []

    def scan(self, target: Target) -> list[Finding]:
        del target
        return list(self.findings)
