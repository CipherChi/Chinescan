# Phase 4A: project log locations and project log analysis

## Step 0

- PR #6 was OPEN, non-draft, mergeable. Every reported PR check was SUCCESS.
- The local `hardening/projects` branch was clean and matched `origin/hardening/projects`; there
  were no unpushed PR #6 fix commits to publish.
- Work began on `hardening/log-locations`, stacked on `hardening/projects`, as PR #6 remains open.
- No merge or approval was performed.

## Implementation

- Added path-private project log location records with project/external scopes, a 20-location cap,
  session-bound project browsing, policy checks at association and job start, metadata-only bounded
  suggestions, EVTX unsupported status, and association-only removal with typed confirmation.
- Added project log job submission for selected or all locations. Each resulting scan is tagged with
  project and location IDs; project detail aggregates alerts, events, timeline entries, and recent
  jobs. Existing source-based `/api/log/jobs` routes continue to use their original path.
- Added CLI `projects logs list|add|remove|suggest|analyze`, project detail UI controls, project and
  external folder selection, suggestion confirmation, job states, and EVTX documentation.
- Successful location responses include only `location_id`, `project_id`, `name`, `scope`, and
  `created_at`. Project responses omit internal roots and event raw references. Log event hashes
  and other normalized event fields are not redacted.

## API shapes

- `GET /api/projects/{id}/browse[?directory_id=...]` returns an opaque project-root selection or a
  directory page using the filesystem browser's session and capability checks.
- `GET /api/projects/{id}/log-locations` returns a list of path-free location records.
- `POST /api/projects/{id}/log-locations` accepts `{ "name", "directory_id", "scope" }`.
- `DELETE /api/projects/{id}/log-locations/{location_id}` accepts `{ "confirmation": "name" }`.
- `POST /api/projects/{id}/log-suggestions` returns `{ "items", "visited", "partial" }`;
  `POST .../log-suggestions/confirm` accepts `{ "suggestion_id", "name" }`.
- `POST /api/projects/{id}/log-jobs` accepts optional `{ "location_ids": [] }` and returns a 202
  log job. Job responses carry `project_id`, `location_ids`, `skipped_counts`, and `error_code`.

## Verification

- Python 3.12.10. Backend suite: 290 passed, 5 opt-in real-scanner tests deselected; 81.54% total
  coverage against an 80% gate.
- Ruff check/format, strict mypy, compileall, pip-audit, and medium+ Bandit passed.
- The project log API flow (create project, suggest, confirm, analyze, show project alerts/events/
  timeline, remove association, verify file hash unchanged) passed twice: 1 passed in 6.61s and
  1 passed in 5.21s.
- CLI/API shared-state parity test passed.
- Full frontend build and unit suite were not runnable locally: the existing `frontend/node_modules`
  lacks `tsc` and `vitest`. Ports 5173 and 8765 had existing listeners, so `npm ci` was skipped as
  instructed. Browser E2E and screenshots were not produced. CI dashboard checks must verify these.
- Gitleaks was not run locally; the existing Docker image is available, but the local executable is
  absent. The branch CI secret scan remains the verification source.
- Tests cover project-relative browse and the selected project log flow at a high level. External
  scope acceptance is not yet tested. Junction
  swaps, a filesystem-open spy, hard-deny precedence for associations, rate-limit exhaustion,
  hash/token pass-through canaries specific to project aggregation, and the complete frontend dialog
  interaction matrix remain to be verified.

## Screenshots

Not captured. The only running frontend/backend listeners were the user's existing processes, and
the local frontend build dependencies were incomplete. No screenshots are claimed.
