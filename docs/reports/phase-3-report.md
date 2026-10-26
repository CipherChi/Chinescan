# Phase 3 verification report

Recorded 2026-10-25 in `C:\src\Chinescan` with Python 3.12.10. Phase 3 adds local reports in
JSON, Markdown, HTML, CSV, and SARIF 2.1.0; investigation case creation/display/status updates;
and scan comparison by finding fingerprint. Records continue to use the configured local SQLite
database.

## Verification results

| Command | Exit | Result |
| --- | ---: | --- |
| `py -3.12 --version` | 0 | `Python 3.12.10`. |
| `py -3.12 -m pytest --cov=chinescan.core --cov-report=term --cov-fail-under=80` | 0 | `28 passed`; core coverage `93.41%`. Python dependencies were exposed from the project `.venv` site-packages for the launcher check. |
| `\.venv\Scripts\ruff.exe check .` | 0 | `All checks passed!`. |
| `\.venv\Scripts\ruff.exe format --check .` | 0 | `60 files already formatted`. |
| `\.venv\Scripts\mypy.exe --strict chinescan` | 0 | `Success: no issues found in 26 source files`. |
| `\.venv\Scripts\pip-audit.exe --skip-editable` | 0 | `No known vulnerabilities found`; editable project distribution skipped. |
| `\.venv312\Scripts\uv.exe lock --check` | 0 | `Resolved 54 packages in 2ms`. |
| `\.venv\Scripts\python.exe -m json.tool schemas\finding.schema.json > $null` | 0 | Valid JSON. |
| `\.venv\Scripts\python.exe -m json.tool schemas\investigation.schema.json > $null` | 0 | Valid JSON; regenerated with the expanded Case record. |
| `docker compose -f docker-compose.yml config --quiet` | 0 | Compose configuration valid. |
| `docker build -f docker/Dockerfile -t chinescan:0.1.0 .` | 0 | Image built from pinned Python digest `sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70`. |
| `docker run --rm chinescan:0.1.0 --help` | 0 | Container help lists `report`, `compare`, and `case` alongside existing commands. |
| `\.venv\Scripts\chinescan.exe code .\fixtures\sample-python-project` | 0 | Three candidate findings, all HIGH; project type `python`. |
| `\.venv\Scripts\chinescan.exe code .\fixtures\sample-node-project --format json` | 0 | JSON summary contains one HIGH candidate; project type `node`; no failures. |
| `\.venv\Scripts\chinescan.exe scan` | 2 | Explicit future-phase stub; expected usage exit code. |

For report CLI verification, a Python fixture scan was persisted to
`tests\phase3-cli.sqlite3`. `chinescan report <scan-id> --format <format> --output <path>` returned
exit 0 for each format: JSON (2,286 bytes), Markdown (687), HTML (870), CSV (793), and SARIF
(3,343). Those report files and the temporary database were removed after the check. The tests
also exercise case creation, case display, status update, scan comparison, secret redaction, HTML
escaping, Markdown escaping, CSV parsing, and SARIF structure.

## Security and scope

- Reports serialize normalized metadata and run shared redaction. HTML text is escaped, Markdown
  text is escaped against raw HTML and common markup, CSV uses the standard quoting writer, and
  SARIF omits source snippets.
- Case workflows only track records, scan/finding IDs, timestamps, and status. They do not declare
  findings resolved or validated on behalf of an analyst.
- Comparison uses stable fingerprints and emits added, resolved, and unchanged identifiers.
- The generic `scan` command remains an explicit exit-2 stub. Log ingestion, malware intake,
  domain assessment, and network services remain outside this phase.
- Phase 2 scanner availability and network-advisory caveats remain as documented in
  `docs/reports/phase-2-report.md`.

## Definition of done

- [x] JSON, Markdown, HTML, CSV, and SARIF 2.1.0 report generation is implemented and checked.
- [x] Cases can be created from a stored scan, displayed, and updated through typed statuses.
- [x] Scan comparisons report added, resolved, and unchanged fingerprint sets.
- [x] Tests cover render formats, escaping/redaction, cases, comparisons, and storage-backed CLI use.
- [x] Python 3.12, Ruff, strict mypy, pytest/coverage, pip-audit, schemas, Compose, fixture scans,
  and Docker image checks pass.

## Next recommended phase

Phase 4: log ingestion, normalized events, timelines, detections, and IOC correlation.
