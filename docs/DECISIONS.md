# Decisions

## ADR-001: Python package and managed dependencies

Use Python 3.12+, with `uv.lock` as the exact transitive resolution. Typer supplies the typed CLI; Pydantic and pydantic-settings validate records and environment-aware settings; SQLAlchemy and Alembic establish persistence and migration boundaries. `tomli-w` safely serializes initialized TOML rather than interpolating user-controlled values into TOML strings. Pytest/pytest-cov, Ruff, mypy, and pip-audit provide the project checks. The planned pytest `<9` range was widened to `<10` after pip-audit reported PYSEC-2026-1845 against 8.4.2, with 9.0.3 listed as a fix. Later-phase scanner and web dependencies are intentionally excluded.

## ADR-002: Local configuration and data defaults

Configuration defaults to `~/.config/chinescan/config.toml`; SQLite defaults to `~/.local/share/chinescan/chinescan.sqlite3`. Explicit config paths and the `CHINESCAN_DATABASE_PATH` setting support local overrides. Config initialization never writes secret settings.

## ADR-003: Versioned generic records

All canonical records inherit a shared `schema_version`. Finding fingerprints are required and use the future stable tuple described in `DEDUPLICATION.md`. SQLite stores JSON-compatible typed payloads behind a repository protocol.
