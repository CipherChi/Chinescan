from chinescan.core.models import Finding, Target
from chinescan.scanners.fake import FakeScanner


def test_fake_scanner_returns_deterministic_copy() -> None:
    finding = Finding(title="Example", fingerprint="example")
    scanner = FakeScanner([finding])
    result = scanner.scan(Target(value="localhost", kind="hostname"))
    assert result == [finding]
    assert result is not scanner.findings
