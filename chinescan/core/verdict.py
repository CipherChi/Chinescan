"""Pure scan verdict calculation and analyst caveats."""

from chinescan.core.models.common import ScanVerdict
from chinescan.core.models.finding import Finding
from chinescan.core.models.investigation import Scan

VERDICT_CAVEAT = {
    verdict: ("Matches are leads rather than proof; no matches do not prove safety.")
    for verdict in ScanVerdict
}


def compute_verdict(scan: Scan, findings: list[Finding]) -> ScanVerdict:
    if scan.status.casefold() in {"failed", "error"} or scan.failures:
        return ScanVerdict.SCAN_FAILED
    if findings:
        return ScanVerdict.LEADS_FOUND
    if scan.coverage is not None and scan.coverage.gaps:
        return ScanVerdict.NO_MATCHES_WITH_GAPS
    return ScanVerdict.NO_MATCHES_IN_SCOPE
