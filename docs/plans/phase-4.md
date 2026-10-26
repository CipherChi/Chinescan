# Phase 4 plan: local log analysis

## Scope

Add local file and directory ingestion, bounded gzip/ZIP reading without extraction, normalized
events, deterministic timelines, built-in authentication/web/process detections, Sigma YAML rules,
IOC matching, alert grouping, and `chinescan logs`. Supported input formats will include JSON,
JSONL, CSV, Linux auth/syslog text, common nginx/Apache/IIS access text, CEF, and LEEF. Windows and cloud
sources are supported through exported JSON/CSV records; native EVTX/journal APIs and live
collectors are out of scope.

## Decisions and safety limits

- Parser, detector, and correlation modules depend on neutral `Event` records and injected services.
- Parse bounded local inputs only. Do not execute commands, start collectors, extract archives, or
  upload logs. Malformed records are counted and skipped without discarding valid events.
- Persist normalized fields and source file/line references, not raw log lines. Redact secret-like
  values in normalized free-text fields and CLI summaries.
- Bound files, directories, archive entries, decompressed bytes, line size, rule size, and regex
  behavior. Reject symbolic links and archive paths are never written to disk.
- Load Sigma YAML with PyYAML `safe_load`; support a documented safe subset of common selectors and
  conditions rather than claiming complete Sigma specification support.
- Built-in detections are candidate alerts for analyst validation. IOC matching is local and uses
  caller-supplied indicators.
- No network listener or external log service is added. Persist events, alerts, timelines, and scan
  metadata in the existing local SQLite repository.

## Implementation and acceptance

1. Extend typed event/alert records and add log parser, normalization, detection, timeline, and IOC
   modules.
2. Add bounded input traversal and JSON, JSONL, CSV, auth/syslog, access-log, CEF, gzip, and ZIP
   readers with line-level failures.
3. Add local built-in rules, Sigma subset evaluation, IOC correlation, alert grouping, and storage.
4. Add `chinescan logs` JSON/human output, deterministic fixtures, and parser/service/CLI tests.
5. Update dependencies and lockfile, schemas, architecture, README, roadmap, ADRs, and this phase's
   verification report.
6. Run Python 3.12, Ruff, strict mypy, pytest with coverage, pip-audit, schema/lock checks, sample
   CLI ingestion, Compose validation, and Docker build; record exact results.
