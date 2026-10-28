"""Local case lifecycle, typed record links, and deterministic case timelines."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import uuid4

from pydantic import BaseModel, ValidationError

from chinescan.core.models.finding import Finding
from chinescan.core.models.investigation import (
    Alert,
    AuthorizationRecord,
    Case,
    CaseActivity,
    CaseActivityType,
    CaseNote,
    CaseRecordLink,
    CaseStatus,
    CaseTimelineItem,
    Event,
    Indicator,
    Scan,
    Target,
    TimelineEntry,
)
from chinescan.core.storage.repository import Repository
from chinescan.malware_analysis.managed import MalwareAnalysisRecord, MalwareSampleRecord

SUPPORTED_CASE_RECORDS: dict[str, type[BaseModel]] = {
    "scan": Scan,
    "finding": Finding,
    "alert": Alert,
    "event": Event,
    "timeline_entry": TimelineEntry,
    "indicator": Indicator,
    "target": Target,
    "authorization_record": AuthorizationRecord,
    "malware_sample": MalwareSampleRecord,
    "malware_analysis": MalwareAnalysisRecord,
}
CASE_STATUS_TRANSITIONS: dict[CaseStatus, set[CaseStatus]] = {
    CaseStatus.OPEN: {CaseStatus.IN_PROGRESS, CaseStatus.RESOLVED, CaseStatus.CLOSED},
    CaseStatus.IN_PROGRESS: {CaseStatus.OPEN, CaseStatus.RESOLVED, CaseStatus.CLOSED},
    CaseStatus.RESOLVED: {CaseStatus.OPEN, CaseStatus.IN_PROGRESS, CaseStatus.CLOSED},
    CaseStatus.CLOSED: set(),
}


class CaseWorkflowError(ValueError):
    """Expected case workflow failure suitable for a usage/data CLI error."""

    exit_code = 2


class CaseNotFoundError(CaseWorkflowError):
    """The requested case does not exist."""


class CaseRecordNotFoundError(CaseWorkflowError):
    """The requested source record does not exist."""


class UnsupportedCaseRecordError(CaseWorkflowError):
    """The source record type is unsupported or is not persisted."""


class InvalidCaseTransitionError(CaseWorkflowError):
    """The requested case status transition is not allowed."""


@dataclass
class CaseContext:
    case: Case
    links: list[CaseRecordLink]
    records: dict[tuple[str, str], BaseModel]
    warnings: list[str]


def _source(record_type: str, record: BaseModel) -> str:
    for field in ("source", "scanner", "kind", "method"):
        value = getattr(record, field, None)
        if isinstance(value, str) and value:
            return value[:200]
    if isinstance(record, Alert):
        return f"rule:{record.rule_id}"[:200]
    if isinstance(record, TimelineEntry):
        return "log_timeline"
    return record_type


def _link(record_type: str, record_id: str, record: BaseModel) -> CaseRecordLink:
    return CaseRecordLink(
        record_type=record_type,
        record_id=record_id,
        source=_source(record_type, record),
        linked_at=datetime.now(UTC),
    )


def _validated_record(repository: Repository, record_type: str, record_id: str) -> BaseModel:
    model = SUPPORTED_CASE_RECORDS.get(record_type)
    if model is None:
        if record_type == "artifact":
            raise UnsupportedCaseRecordError(
                "Artifact records are not persisted in this release and cannot be linked."
            )
        supported = ", ".join(sorted(SUPPORTED_CASE_RECORDS))
        raise UnsupportedCaseRecordError(
            f"Unsupported record type '{record_type}'. Persisted types: {supported}."
        )
    payload = repository.get(record_type, record_id)
    if payload is None:
        raise CaseRecordNotFoundError(f"{record_type} record not found: {record_id}")
    try:
        return model.model_validate(payload)
    except (ValidationError, ValueError, TypeError) as exc:
        raise CaseWorkflowError(f"Stored {record_type} record is invalid.") from exc


def _case(repository: Repository, case_id: str) -> Case:
    payload = repository.get("case", case_id)
    if payload is None:
        raise CaseNotFoundError(f"Case not found: {case_id}")
    try:
        return Case.model_validate(payload)
    except (ValidationError, ValueError, TypeError) as exc:
        raise CaseWorkflowError("Stored case data is invalid.") from exc


class CaseWorkflow:
    """Manage a case and its append-only notes/activity in one stored case record."""

    def __init__(self, repository: Repository) -> None:
        self.repository = repository

    def create_from_scan(
        self,
        scan_id: str,
        *,
        title: str | None = None,
        description: str = "",
        severity: str = "medium",
    ) -> tuple[Case, list[str]]:
        title = title.strip() if title is not None else ""
        if title and len(title) > 200:
            raise CaseWorkflowError("Case title exceeds the 200 character limit.")
        if len(description) > 8_000:
            raise CaseWorkflowError("Case description exceeds the 8000 character limit.")
        scan = _validated_record(self.repository, "scan", scan_id)
        assert isinstance(scan, Scan)
        now = datetime.now(UTC)
        links = [_link("scan", scan_id, scan)]
        warnings: list[str] = []
        refs = [("target", scan.target_id)]
        refs.extend(("finding", item) for item in scan.finding_ids)
        refs.extend(("alert", item) for item in scan.alert_ids)
        refs.extend(("event", item) for item in scan.event_ids)
        refs.extend(("timeline_entry", item) for item in scan.timeline_entry_ids)
        for record_type, record_id in refs:
            self._append_existing_link(links, record_type, record_id, warnings)
        case = Case(
            title=title or f"Investigation for {scan_id}",
            description=description,
            severity=severity,
            created_at=now,
            updated_at=now,
            scan_ids=[scan_id],
            finding_ids=list(scan.finding_ids),
            links=links,
            activities=[
                CaseActivity(
                    activity_type=CaseActivityType.CREATED,
                    occurred_at=now,
                    details={"from_scan": scan_id, "linked_record_count": str(len(links))},
                )
            ],
        )
        self.repository.save("case", case.case_id, case.model_dump(mode="json"))
        return case, warnings

    def get_case(self, case_id: str) -> Case:
        return _case(self.repository, case_id)

    def update_status(self, case_id: str, status: CaseStatus) -> tuple[Case, bool]:
        case = _case(self.repository, case_id)
        if status == case.status:
            return case, False
        if status not in CASE_STATUS_TRANSITIONS[case.status]:
            raise InvalidCaseTransitionError(
                f"Cannot change case status from {case.status.value} to {status.value}."
            )
        now = datetime.now(UTC)
        updated = case.model_copy(
            update={
                "status": status,
                "updated_at": now,
                "activities": [
                    *case.activities,
                    CaseActivity(
                        activity_type=CaseActivityType.STATUS_CHANGED,
                        occurred_at=now,
                        details={"from": case.status.value, "to": status.value},
                    ),
                ],
            }
        )
        self._save(updated)
        return updated, True

    def link_record(
        self, case_id: str, record_type: str, record_id: str
    ) -> tuple[Case, bool, list[str]]:
        case = _case(self.repository, case_id)
        record = _validated_record(self.repository, record_type, record_id)
        context = self.context(case)
        key = (record_type, record_id)
        if key in context.records:
            return case, False, context.warnings
        links = [*case.links, _link(record_type, record_id, record)]
        refs = [(record_type, record_id)]
        warnings = list(context.warnings)
        if isinstance(record, Scan):
            refs.append(("target", record.target_id))
            refs.extend(("finding", item) for item in record.finding_ids)
            refs.extend(("alert", item) for item in record.alert_ids)
            refs.extend(("event", item) for item in record.event_ids)
            refs.extend(("timeline_entry", item) for item in record.timeline_entry_ids)
        for related_type, related_id in refs[1:]:
            self._append_existing_link(links, related_type, related_id, warnings)
        scan_ids = list(
            dict.fromkeys([*case.scan_ids, *([record_id] if record_type == "scan" else [])])
        )
        finding_ids = list(
            dict.fromkeys([*case.finding_ids, *([record_id] if record_type == "finding" else [])])
        )
        now = datetime.now(UTC)
        updated = case.model_copy(
            update={
                "links": links,
                "scan_ids": scan_ids,
                "finding_ids": finding_ids,
                "updated_at": now,
                "activities": [
                    *case.activities,
                    CaseActivity(
                        activity_type=CaseActivityType.RECORD_LINKED,
                        occurred_at=now,
                        details={
                            "record_type": record_type,
                            "record_id": record_id,
                            "additional_links": str(max(0, len(links) - len(context.links) - 1)),
                        },
                    ),
                ],
            }
        )
        self._save(updated)
        return updated, True, warnings

    def add_note(self, case_id: str, body: str, author_label: str | None = None) -> CaseNote:
        case = _case(self.repository, case_id)
        body = body.strip()
        if not body:
            raise CaseWorkflowError("Note text must not be empty.")
        if len(body) > 8_000:
            raise CaseWorkflowError("Note text exceeds the 8000 character limit.")
        if author_label is not None:
            author_label = author_label.strip()
            if not author_label or len(author_label) > 100:
                raise CaseWorkflowError("Author label must contain 1 to 100 characters.")
        now = datetime.now(UTC)
        note = CaseNote(
            note_id=str(uuid4()),
            case_id=case_id,
            body=body,
            created_at=now,
            author_label=author_label,
        )
        updated = case.model_copy(
            update={
                "notes": [*case.notes, note],
                "updated_at": now,
                "activities": [
                    *case.activities,
                    CaseActivity(
                        activity_type=CaseActivityType.NOTE_ADDED,
                        occurred_at=now,
                        details={"note_id": note.note_id},
                    ),
                ],
            }
        )
        self._save(updated)
        return note

    def context(self, case: Case | str) -> CaseContext:
        if isinstance(case, str):
            case = _case(self.repository, case)
        links: list[CaseRecordLink] = list(case.links)
        seen = {(item.record_type, item.record_id) for item in links}
        legacy_refs = [("scan", item) for item in case.scan_ids]
        legacy_refs.extend(("finding", item) for item in case.finding_ids)
        for record_type, record_id in legacy_refs:
            if (record_type, record_id) not in seen:
                links.append(
                    CaseRecordLink(
                        record_type=record_type,
                        record_id=record_id,
                        source="legacy_case_reference",
                        linked_at=None,
                    )
                )
                seen.add((record_type, record_id))

        records: dict[tuple[str, str], BaseModel] = {}
        warnings: list[str] = []
        index = 0
        while index < len(links):
            link = links[index]
            index += 1
            key = (link.record_type, link.record_id)
            if key in records:
                continue
            try:
                record = _validated_record(self.repository, link.record_type, link.record_id)
            except CaseWorkflowError as exc:
                warnings.append(str(exc))
                continue
            records[key] = record
            if isinstance(record, Scan):
                related = [("target", record.target_id)]
                related.extend(("finding", item) for item in record.finding_ids)
                related.extend(("alert", item) for item in record.alert_ids)
                related.extend(("event", item) for item in record.event_ids)
                related.extend(("timeline_entry", item) for item in record.timeline_entry_ids)
                for related_type, related_id in related:
                    if (related_type, related_id) not in seen:
                        try:
                            related_record = _validated_record(
                                self.repository, related_type, related_id
                            )
                        except CaseWorkflowError as exc:
                            warnings.append(str(exc))
                            continue
                        links.append(_link(related_type, related_id, related_record))
                        seen.add((related_type, related_id))
                        records[(related_type, related_id)] = related_record
        if any(
            isinstance(item, Finding) and not hasattr(item, "remediation")
            for item in records.values()
        ):
            warnings.append("No structured remediation guidance is stored for linked findings.")
        if any(isinstance(item, CaseNote) for item in case.notes):
            warnings.append(
                "Author labels are locally supplied and are not authenticated identities."
            )
        return CaseContext(
            case=case, links=links, records=records, warnings=list(dict.fromkeys(warnings))
        )

    def timeline(self, case: Case | str) -> tuple[Case, list[CaseTimelineItem], list[str]]:
        context = self.context(case)
        items: list[tuple[datetime, CaseTimelineItem]] = []
        for activity in context.case.activities:
            items.append(
                (
                    _sort_time(activity.occurred_at),
                    CaseTimelineItem(
                        item_id=f"activity:{activity.activity_id}",
                        category="case_activity",
                        description=_activity_description(activity),
                        case_activity_at=activity.occurred_at,
                        record_type="case_activity",
                        record_id=activity.activity_id,
                        source="local_case_workflow",
                    ),
                )
            )
        source_event_ids = {
            entry.event_id
            for (kind, _), entry in context.records.items()
            if kind == "timeline_entry" and isinstance(entry, TimelineEntry) and entry.event_id
        }
        for (_, _), record in context.records.items():
            if isinstance(record, Event):
                source_event_ids.discard(record.event_id)
                items.append(
                    (
                        _sort_time(record.occurred_at),
                        CaseTimelineItem(
                            item_id=f"event:{record.event_id}",
                            category="source_event",
                            description=record.summary,
                            event_occurred_at=record.occurred_at,
                            record_type="event",
                            record_id=record.event_id,
                            source=record.source,
                        ),
                    )
                )
        for (_, _), record in context.records.items():
            if isinstance(record, TimelineEntry) and (
                not record.event_id or record.event_id in source_event_ids
            ):
                items.append(
                    (
                        _sort_time(record.occurred_at),
                        CaseTimelineItem(
                            item_id=f"timeline:{record.entry_id}",
                            category="source_timeline",
                            description=record.description,
                            event_occurred_at=record.occurred_at,
                            record_type="timeline_entry",
                            record_id=record.entry_id,
                            source="log_timeline",
                        ),
                    )
                )
        items.sort(
            key=lambda pair: (
                pair[0],
                pair[1].category,
                pair[1].record_type or "",
                pair[1].record_id or "",
                pair[1].item_id,
            )
        )
        return context.case, [item for _, item in items], context.warnings

    def _append_existing_link(
        self,
        links: list[CaseRecordLink],
        record_type: str,
        record_id: str,
        warnings: list[str],
    ) -> None:
        if any(link.record_type == record_type and link.record_id == record_id for link in links):
            return
        try:
            record = _validated_record(self.repository, record_type, record_id)
        except CaseWorkflowError as exc:
            warnings.append(str(exc))
            return
        links.append(_link(record_type, record_id, record))

    def _save(self, case: Case) -> None:
        self.repository.save("case", case.case_id, case.model_dump(mode="json"))


def _sort_time(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _activity_description(activity: CaseActivity) -> str:
    details = activity.details
    if activity.activity_type == CaseActivityType.CREATED:
        return f"Case created from scan {details.get('from_scan', 'unspecified')}."
    if activity.activity_type == CaseActivityType.STATUS_CHANGED:
        return f"Status changed from {details.get('from')} to {details.get('to')}."
    if activity.activity_type == CaseActivityType.RECORD_LINKED:
        return f"Linked {details.get('record_type')} record {details.get('record_id')}."
    return f"Added analyst note {details.get('note_id')}."
