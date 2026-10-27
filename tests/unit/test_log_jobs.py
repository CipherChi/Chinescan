import threading
from pathlib import Path

import pytest

from chinescan.web.log_jobs import LogJobManager, LogSourceRegistry


def _source_config(config: Path, root: Path) -> Path:
    config.write_text(
        f'[[sources]]\nid = "local"\nname = "Local source"\nroot = "{root.as_posix()}"\n',
        encoding="utf-8",
    )
    return config


def test_registry_hides_protected_roots_and_rejects_escape_from_request(repository, tmp_path):
    protected = tmp_path / "protected"
    protected.mkdir()
    config = _source_config(tmp_path / "sources.toml", protected / "logs")
    (protected / "logs").mkdir()
    registry = LogSourceRegistry(config, [protected])
    assert registry.entries() == []
    with pytest.raises(ValueError, match="unavailable"):
        registry.resolve("local")


def test_queue_limit_and_restart_reconciliation(repository, tmp_path):
    root = tmp_path.parent / f"{tmp_path.name}-logs"
    root.mkdir()
    (root / "auth.jsonl").write_text('{"message":"synthetic"}\n', encoding="utf-8")
    config = _source_config(tmp_path / "sources.toml", root)
    registry = LogSourceRegistry(config, [repository.path.parent])
    manager = LogJobManager(repository, threading.RLock(), registry, queue_limit=2)
    manager.submit("local")
    manager.submit("local")
    with pytest.raises(OverflowError):
        manager.submit("local")

    repository.save(
        "log_job",
        "abandoned",
        {"job_id": "abandoned", "status": "running", "created_at": "2026-01-01T00:00:00+00:00"},
    )
    restart = LogJobManager(repository, threading.RLock(), registry)
    restart.start()
    restart.stop()
    saved = repository.get("log_job", "abandoned")
    assert saved is not None
    assert saved["status"] == "interrupted"
    assert saved["error"] == "Server restarted before the job completed."
