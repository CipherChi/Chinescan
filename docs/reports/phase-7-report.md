# Phase 7 report: evidence, coverage, report storage, and offline indicators

Date: 2026-10-29

## Scope delivered

- Added optional Finding evidence, Scan coverage/verdict fields, backward-compatible persistence,
  verdict calculation, and generated JSON Schema exports.
- Added configurable report storage, immutable JSON/Markdown auto-save for code scans, CLI report
  controls, coverage summaries, and the share-summary projection.
- Added offline local indicator-file scanning, including existing `load_iocs` inputs and bounded
  STIX/MISP handling, plus coverage diagnostics.
- Added dashboard scan verdict/coverage display and code-job report-save warnings. Scan API models
  remain explicit allowlists and expose the new scan summary/detail fields as optional additions.
- Updated environment, architecture, decision, responsible-use, README, API, log-source, and
  malware-backend wording. No external project was consulted or reused.

## Acceptance commands

Commands were run in `C:\src\Chinescan` using the project `.venv` managed by plain `uv`.

### `uv lock --check`

```text
Resolved 76 packages in 32ms
Exit code: 0
```

### `uv run --locked --extra dev ruff check .`

```text
All checks passed!
Exit code: 0
```

### `uv run --locked --extra dev mypy --strict chinescan`

```text
Success: no issues found in 55 source files
Exit code: 0
```

### `uv run --locked --extra dev pytest -q`

```text
........................................................................ [ 75%]
.....                           [100%]
190 passed, 5 deselected in 126.49s (0:02:06)
Exit code: 0
```

### `py -3.12 --version`

```text
Python 3.12.10
Exit code: 0
```

Frontend checks were also run from `frontend/`:

- `npm run typecheck`: exit 0.
- `npm test -- --run`: 4 test files passed; 8 tests passed.

## Behavior notes and limits

- Existing persisted Scan/Finding payloads without the new optional fields still validate.
- Report auto-save is limited to code scans. Log, malware, and domain scans do not auto-save reports.
- `domain_assessment/probe.py` retains its existing authorized network behavior. Offline-only applies
  to the new indicator scanner.
- The dashboard API retains path-free explicit response models; new verdict and gap count fields
  are optional, and scan detail includes optional coverage and failures.
- Coverage reports include source file count, bytes, scanner count, scanner failures, and observed
  indicator-scanner gaps. Code discovery retains its existing source-file caps and oversized-file
  abort behavior.
- `CodeScanService` isolates scanner failures, keeps findings returned by successful scanners, and
  stores failures plus a scanner-failure coverage gap. Discovery-level aborts persist a failed scan
  when a repository is available, then preserve the existing raised `ScannerError` behavior.
- The indicator scanner accepts local inputs only and performs no DNS, socket, HTTP, subprocess, or
  domain-assessment operations. Unsupported STIX patterns and malformed indicator entries produce
  coverage gaps. Indicator matching is limited to supported normalized forms and bounded local
  project file traversal.
- The CLI's `--fail-on-gaps` is opt-in and returns existing exit code 1 when coverage gaps exist.
  Report-store errors remain warnings and do not change the scan exit result.
- No commit, push, staging, global tool installation, report-history edit, or bundle-file edit was
  performed.

## Changed user-facing wording

- Replaced the malware job's “no clean verdict” message with “no scan verdict”.
- Changed the case-report empty line from “No findings linked” to “This case has no linked finding
  records.”
- Changed the log guidance from “clean results” to “complete results”.
- Changed API log-job guidance from “clean analysis” to “complete analysis”.
- Changed log and malware analysis guidance from “clean result” to incomplete-analysis wording.
- Changed the malware verdict wording so it does not describe a “safe” verdict.
- Changed the dashboard empty state from “No findings to review” to “No persisted finding records”.
- Changed the dashboard malware completion copy to say to validate indicators before drawing
  conclusions.
- Changed the dashboard scan response-model docstring and domain probe docstring to describe
  reviewed output and bounded requests without using “safe” as a product assurance.
- Added the required explicit verdict caveat wherever a recorded verdict is presented.

Other occurrences of “safe” in source/docs describe specific implementation properties, such as
safe YAML parsing or safe path handling, rather than a scan verdict. Historical phase reports were
not changed.
