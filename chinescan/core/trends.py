"""Build privacy-conscious daily summaries from locally stored scan records."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, date, datetime, timedelta
from typing import Any

from chinescan.core.models.common import Severity
from chinescan.core.models.finding import Finding
from chinescan.core.models.investigation import Alert, Scan


def scan_history_trends(
    scans: Iterable[dict[str, Any]],
    findings: Iterable[dict[str, Any]],
    alerts: Iterable[dict[str, Any]],
    *,
    days: int = 30,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Return daily scan, finding, and alert counts without exposing target data."""
    if not 1 <= days <= 366:
        raise ValueError("days must be between 1 and 366")
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    end_date = current.astimezone(UTC).date()
    start_date = end_date - timedelta(days=days - 1)
    daily: dict[date, dict[str, Any]] = {
        start_date + timedelta(days=offset): {
            "date": (start_date + timedelta(days=offset)).isoformat(),
            "scans": 0,
            "findings": 0,
            "findings_by_severity": {severity.value: 0 for severity in Severity},
            "alerts": 0,
            "alerts_by_severity": {severity.value: 0 for severity in Severity},
        }
        for offset in range(days)
    }
    finding_by_id = {
        finding.finding_id: finding for finding in map(Finding.model_validate, findings)
    }
    alert_by_id = {alert.alert_id: alert for alert in map(Alert.model_validate, alerts)}
    included = [Scan.model_validate(payload) for payload in scans]

    for scan in included:
        scan_date = scan.started_at.astimezone(UTC).date()
        if scan_date not in daily:
            continue
        bucket = daily[scan_date]
        bucket["scans"] += 1
        for finding_id in scan.finding_ids:
            finding = finding_by_id.get(finding_id)
            if finding is not None:
                bucket["findings"] += 1
                bucket["findings_by_severity"][finding.severity.value] += 1
        for alert_id in scan.alert_ids:
            alert = alert_by_id.get(alert_id)
            if alert is not None:
                bucket["alerts"] += 1
                bucket["alerts_by_severity"][alert.severity.value] += 1

    ordered = [daily[day] for day in sorted(daily)]
    return {
        "days": days,
        "start_date": start_date.isoformat(),
        "end_date": end_date.isoformat(),
        "total_scans": sum(item["scans"] for item in ordered),
        "daily": ordered,
    }
