# ChineScan

ChineScan is an authorization-first, modular security investigation platform. Phase 1 establishes its Python package, typed records, configuration, structured logging, local SQLite persistence, and command-line interface. Network scanning and other operational workflows are reserved for later phases.

## Requirements

- Python 3.12 or newer
- `uv` for environment and dependency management

## Quick start

```powershell
uv sync --extra dev
uv run chinescan --help
uv run chinescan version
```

Initialize a local configuration with `uv run chinescan config init`; provide `--path` to choose a location. Initialization writes no credentials. The SQLite database defaults to the platform user-data directory and can be overridden with `CHINESCAN_DATABASE_PATH`.

## Safety boundary

Only use ChineScan against assets for which you have explicit authorization. Phase 1 does not implement scanning, malware intake, or a network service. See [Responsible Use](docs/RESPONSIBLE_USE.md).
