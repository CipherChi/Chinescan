# Development

Use Python 3.12+ and `uv`:

```powershell
uv sync --extra dev
uv run ruff check .
uv run mypy chinescan
uv run pytest --cov=chinescan --cov-report=term-missing --cov-fail-under=80
uv run pip-audit --skip-editable
```

Run the CLI with `uv run chinescan --help`. The test suite uses temporary configuration and SQLite files. Do not point tests at personal data. Keep dependency changes in `pyproject.toml` and regenerate `uv.lock` with `uv lock`.
