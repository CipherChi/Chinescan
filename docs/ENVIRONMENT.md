# Environment and repository orientation

Recorded on 2026-10-25 from the Windows workspace.

## Repository

- Project root: `C:\src\Chinescan`, an independent Git repository nested inside the unrelated parent checkout `C:\src`.
- The parent checkout and sibling projects are outside this repository and must not be modified or staged here.
- Phase 0 documentation was prepared before project initialization; no application code existed at that point.

## Python 3.12 start gate

Commands run after installing the authorized Python 3.12 runtime:

- `py -0` -> exit 0:
  ```text
   -V:3.13 *        Python 3.13 (64-bit)
   -V:3.12          Python 3.12 (64-bit)
   -V:3.11          Python 3.11 (64-bit)
   -V:3.10          Python 3.10 (64-bit)
  ```
- `py -3.12 --version` -> exit 0: `Python 3.12.10`.

Python 3.12.10 is the required acceptance interpreter. An existing `.venv` was present and used Python 3.13.15. During `uv sync`, uv replaced `.venv` with a Python 3.12.10 environment; this was an unplanned local environment change. The `.venv312` environment contains the uv tool used to manage the project environment.

## Earlier Phase 0 environment observations

The original orientation found Python 3.10.11 as the default `python`, Docker CLI 29.9.2, pip 23.0.1 for Python 3.10, and no `uv`, Semgrep, pytest, Ruff, mypy, or hadolint on PATH. See `docs/reports/phase-0-report.md` for the full historical record. These observations predate Python 3.12.10 installation.

## Phase 1 constraints

- Require Python 3.12+; do not weaken this constraint.
- Keep all project changes in this nested repository; never stage content into `C:\src`.
- Do not claim malware sample storage or later-phase scanning workflows are implemented.
- Record exact verification outputs, including any unavailable Docker daemon, in `docs/reports/phase-1-report.md`.
