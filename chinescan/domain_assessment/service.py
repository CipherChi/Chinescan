"""Audited orchestration for one explicitly authorized domain posture assessment."""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from chinescan.core.models.common import Confidence, FindingCategory, Severity
from chinescan.core.models.finding import Finding
from chinescan.core.models.investigation import AuthorizationRecord, Scan, Target
from chinescan.core.storage.repository import Repository
from chinescan.domain_assessment.authorization import AuthorizationGrant
from chinescan.domain_assessment.probe import DomainProbe, NetworkDomainProbe, ProbeResult


@dataclass(frozen=True)
class DomainScanResult:
    scan_id: str
    target: str
    profile: str
    authorization_id: str
    probe: ProbeResult
    findings: tuple[Finding, ...]
    status: str
    scan_options: dict[str, str | int | float | bool]

    def summary(self) -> dict[str, object]:
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "profile": self.profile,
            "authorization_id": self.authorization_id,
            "status": self.status,
            "scan_options": self.scan_options,
            "probe": self.probe.summary(),
            "finding_count": len(self.findings),
            "findings": [finding.model_dump(mode="json") for finding in self.findings],
        }


class DomainAssessmentService:
    """Persist explicit authorization before calling the injected network probe."""

    def __init__(
        self,
        repository: Repository,
        probe: DomainProbe | None = None,
        *,
        scan_options: dict[str, str | int | float | bool] | None = None,
    ) -> None:
        self.repository = repository
        self.probe = probe or NetworkDomainProbe()
        self.scan_options = scan_options or {}

    def assess(self, grant: AuthorizationGrant) -> DomainScanResult:
        started = datetime.now(UTC)
        scan_id = str(uuid.uuid4())
        target_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"domain:{grant.target}"))
        authorization = AuthorizationRecord(
            target=grant.target,
            method=grant.method,
            operator=grant.operator,
            authorized_at=grant.authorized_at,
            valid_until=grant.valid_until,
            scan_profile=grant.profile,
            scan_id=scan_id,
        )
        target = Target(value=grant.target, kind="domain")
        self.repository.save("target", target_id, target.model_dump(mode="json"))
        self.repository.save(
            "authorization_record",
            authorization.authorization_id,
            authorization.model_dump(mode="json"),
        )
        self.repository.save(
            "scan",
            scan_id,
            Scan(
                scan_id=scan_id,
                target_id=target_id,
                scanner=self.probe.name,
                started_at=started,
                status="running",
                scan_options=self.scan_options,
            ).model_dump(mode="json"),
        )

        try:
            probe_result = self.probe.assess(grant.target, grant.profile)
            findings = tuple(_finding(grant.target, item) for item in probe_result.findings)
            status = "partial" if probe_result.errors else "complete"
            failures = {
                f"probe_{index}": error for index, error in enumerate(probe_result.errors, 1)
            }
        except Exception:
            probe_result = ProbeResult(errors=("Domain probe failed unexpectedly",))
            findings = ()
            status = "partial"
            failures = {"probe": "Domain probe failed unexpectedly"}
        finished = datetime.now(UTC)
        self.repository.save(
            "scan",
            scan_id,
            Scan(
                scan_id=scan_id,
                target_id=target_id,
                scanner=self.probe.name,
                started_at=started,
                finished_at=finished,
                status=status,
                project_types=["domain", grant.profile],
                finding_ids=[finding.finding_id for finding in findings],
                failures=failures,
                scan_options=self.scan_options,
            ).model_dump(mode="json"),
        )
        for finding in findings:
            self.repository.save("finding", finding.finding_id, finding.model_dump(mode="json"))
        return DomainScanResult(
            scan_id,
            grant.target,
            grant.profile,
            authorization.authorization_id,
            probe_result,
            findings,
            status,
            self.scan_options,
        )


def _finding(hostname: str, item: tuple[str, str, str, str]) -> Finding:
    rule_id, title, severity_text, description = item
    fingerprint = hashlib.sha256(f"{hostname}|{rule_id}".encode()).hexdigest()
    severity = Severity(severity_text)
    category = (
        FindingCategory.TLS if "TLS" in rule_id or "HTTPS" in rule_id else FindingCategory.WEB
    )
    return Finding(
        finding_id=str(uuid.uuid5(uuid.NAMESPACE_URL, fingerprint)),
        title=title,
        description=description,
        severity=severity,
        fingerprint=fingerprint,
        category=category,
        confidence=Confidence.POSSIBLE,
        scanner="builtin-domain-posture",
        rule_id=rule_id,
        location=f"https://{hostname}/",
        tags=["candidate", "authorized-domain-assessment", "heuristic"],
    )
