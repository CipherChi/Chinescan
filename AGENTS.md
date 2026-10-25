# ChineScan repository conventions

- The project root is `C:\src\Chinescan`, a standalone Git repository nested in another checkout. Keep all changes and Git operations scoped to this repository.
- Require Python 3.12 or newer. Use `py -3.12` for acceptance checks; do not rely on the default interpreter.
- Do not scan or modify sibling projects or the parent checkout.
- Do not commit or push unless the user explicitly asks.
- Keep Phase 1 limited to its documented platform foundation. Future-phase CLI commands must remain explicit stubs and return usage exit code 2.
- Configuration initialization must never write secret values. Redact secrets from logs.
- SQLite uses a local configurable data path; do not expose a network listener.
- Do not claim Windows POSIX mode bits enforce ACL protections, and do not claim malware intake/storage is implemented.
- Run the acceptance commands documented in `docs/plans/phase-1.md` and capture exact results in `docs/reports/phase-1-report.md`.
