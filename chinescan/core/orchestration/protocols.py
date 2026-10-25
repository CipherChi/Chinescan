"""Protocols implemented by scanner and analysis adapters."""

from typing import Protocol, TypeVar

from chinescan.core.models.finding import Finding
from chinescan.core.models.investigation import Target

T = TypeVar("T")


class ScannerAdapter(Protocol):
    name: str

    def scan(self, target: Target) -> list[Finding]: ...


class Analyzer(Protocol):
    name: str

    def analyze(self, value: T) -> T: ...
