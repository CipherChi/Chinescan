# Phase 5A diagnostics verification

Verification ran on `hardening/diagnostics`. Backend tests used pytest basetemp under the OS temp directory. Browser tests ran from the OS-temp repository copy, using isolated fixture data and ephemeral loopback listeners. No real credential, config, or database files were used; no existing listener was changed.

## Results

- Backend: `uv run pytest --cov=chinescan --cov-report=term-missing --cov-fail-under=80` — 335 passed, 5 deselected by the existing optional scanner fixture policy; overall coverage 81.62%; `chinescan/core/diagnostics.py` coverage 92% (186 statements, 14 missed).
- Focused diagnostics tests: 15 passed twice before the final full-suite runs.
- Ruff check and format check passed; strict mypy passed for 64 source files; Bandit `-ll` found 0 medium/high issues; compileall passed.
- Frontend typecheck and build passed. Vitest passed three consecutive runs: 44 tests each.
- Isolated System status Playwright specs passed: 3 tests. Full Playwright suite passed twice consecutively: 15 tests each.
- `git diff main -- docs/reports/phase-1-report.md` is empty. Phase 5A notes are maintained here.
- Gitleaks is unavailable locally.

The status UI's **Check now** button triggers all three diagnostic requests immediately, announces progress/results in a live region, and is disabled during the request. Healthy polling is 30 seconds. Failed connections retry at 1, 2, 4, 8, 16, 32, then 60 seconds repeatedly until recovery; successful checks reset the retry delay. An unauthenticated browser session is redirected to operator login before detailed status panels appear.

## API and checks

- `GET /api/health` is unauthenticated and returns only `status`, `app_name`, `version`, `uptime_seconds`, `bind_address`, and `timestamp`.
- Authenticated `GET /api/ready` returns `{state, checks, allowed_roots}`. Each check is `{id, label, state, detail, action_hint}`. It returns 200 for healthy/degraded and 503 for failure.
- Authenticated `GET /api/diagnostics` includes platform/runtime and app versions, config/storage status, operator state, allowed-root and deny-list counts, feature flags, scan bounds, record counts, the checks, and up to 50 redacted recent error summaries.

Doctor check IDs: `config`, `credentials`, `filesystem-policy`, `directories`, `database`, `frontend`, `managed-malware`, `offline`, `uv`, `node-npm`, `frontend-dependencies`, `port-5173`, `port-8765`, and `python-environment`.

## Audit mapping

| Item | Test |
| --- | --- |
| Minimal health payload, public health, authenticated ready/diagnostics, Host/Origin guards | `test_health_report_is_minimal_and_path_free`; `test_diagnostics_routes_are_loopback_guarded_and_authenticated`; `test_diagnostics_rate_limit_host_and_origin_guards` |
| Healthy/degraded/failing readiness including credentials, DB, directories, frontend, allowed roots | `test_ready_healthy_returns_all_pass_and_diagnostics_matches_cli`; `test_ready_degraded_for_invalid_allowed_root_and_missing_optional_storage`; `test_ready_fails_for_corrupt_credentials_unwritable_database_missing_dirs_and_frontend` |
| Cross-surface planted secret/path canary | `test_canary_does_not_appear_in_api_or_cli_outputs_or_errors` |
| Error ring bounded and excludes request data | `test_diagnostics_error_ring_is_bounded_and_excludes_request_data` |
| DB probe does not retain rows | `test_report_is_path_free_and_checks_database_read_only` |
| Doctor mocks, exit codes, NO_COLOR, JSON, environment breakage | `test_doctor_exit_codes_json_shape_and_no_color`; `test_doctor_local_probes_and_python_environment_mocks` |
| Doctor does not use remote sockets or modify config/tree | `test_doctor_is_read_only_and_does_not_make_remote_socket_calls` |
| CLI/API parity | `test_ready_healthy_returns_all_pass_and_diagnostics_matches_cli` |
| Frontend healthy/degraded/failing and accessible live region | `renders healthy status and accessible live updates`; `renders degraded readiness with its action hint`; `renders failing readiness checks from a 503 response and diagnostics summaries` |
| Manual refresh, in-flight disabled state, capped backoff, recovery reset, unmount cleanup, unauthorized callback | `Check now starts one refresh, disables while in flight, then re-enables`; `uses non-decreasing exponential retry intervals capped at 60 seconds`; `resets retry delay after recovery`; `stops polling and clears timers on unmount`; `redirects an unauthenticated session through the unauthorized callback` |
| Browser healthy/offline/recovery, degraded optional storage, unauthenticated behavior | `system status is healthy, goes offline, then recovers`; `system status reports degraded readiness for missing optional storage`; `unauthenticated status view redirects to operator login` |

## Browser screenshots

- Healthy: `%TEMP%\chinescan-phase5a-status-screenshots\system-status-healthy.png`
- Degraded: `%TEMP%\chinescan-phase5a-status-screenshots\system-status-degraded.png`
- Offline: `%TEMP%\chinescan-phase5a-status-screenshots\system-status-offline.png`

The offline browser test blocks the three API requests from the page, presses **Check now**, verifies the offline state, then removes the routes and checks recovery. The separate unit test exercises retry timing and its cap.
