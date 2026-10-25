# Architecture

Phase 1 separates the Typer CLI, validated Pydantic records, configuration and logging utilities, orchestration protocols, and persistence. Scanner adapters implement `ScannerAdapter`; analyzers implement `Analyzer`. The fake adapter is deterministic and does not perform network activity.

The SQLite repository provides local persistence behind the `Repository` protocol. Its initial table stores typed record payloads as JSON with a record type and ID. Alembic owns schema evolution. Settings accept `CHINESCAN_` environment overrides and default the database under the user's data directory.

The CLI is a thin boundary: configuration and version are implemented; later-phase operations report their target phase and exit with code 2. No service listener or scan orchestration is enabled in Phase 1.

All canonical records carry `schema_version` (currently `1.0`). `Finding.fingerprint` is required; its canonical tuple contract is documented in [Deduplication](DEDUPLICATION.md).
