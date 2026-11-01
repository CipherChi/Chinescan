"""GitHub source validation tests; fixtures are constructed from runtime strings."""

import ctypes
import io
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

import chinescan.core.github_import as github_import_core
from chinescan.cli.app import app
from chinescan.core.accounts import create_operator
from chinescan.core.config.settings import Settings
from chinescan.core.github_import import (
    GitHubImportError,
    GitHubImportService,
    build_clone_argv,
    build_git_environment,
    validate_github_url,
    validate_ref,
)
from chinescan.core.storage.sqlite import SQLiteRepository
from chinescan.web.app import create_app


def _git(*args: str, cwd: Path | None = None, input_text: str | None = None) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=cwd,
        input=input_text,
        text=True,
        capture_output=True,
        shell=False,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


def _bare_repo(tmp_path: Path, files: dict[str, str] | None = None) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    work = tmp_path / "work"
    work.mkdir()
    _git("init", str(work))
    _git("config", "user.name", "Runtime Fixture", cwd=work)
    _git("config", "user.email", "fixture@example.test", cwd=work)
    for name, content in (files or {"README.txt": "local fixture\n"}).items():
        target = work.joinpath(*name.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    _git("add", "--all", cwd=work)
    _git("commit", "-m", "runtime fixture", cwd=work)
    bare = tmp_path / "fixture.git"
    _git("clone", "--bare", str(work), str(bare))
    return bare


def _raw_object(bare: Path, kind: str, body: bytes) -> str:
    result = subprocess.run(
        ["git", "--git-dir", str(bare), "hash-object", "--literally", "-t", kind, "-w", "--stdin"],
        input=body,
        capture_output=True,
        shell=False,
        check=False,
    )
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    return result.stdout.decode("ascii").strip()


def _windows_short_path(path: Path) -> Path:
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    get_short_path = kernel.GetShortPathNameW
    get_short_path.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32]
    get_short_path.restype = ctypes.c_uint32
    required = get_short_path(str(path), None, 0)
    if required == 0:
        pytest.skip("Windows did not provide an 8.3 alias for the temporary test directory.")
    buffer = ctypes.create_unicode_buffer(required)
    written = get_short_path(str(path), buffer, required)
    if written == 0 or written >= required:
        pytest.skip("Windows did not provide a usable 8.3 alias for the temporary test directory.")
    return Path(buffer.value)


def _publish_raw_tree(bare: Path, tree_body: bytes) -> None:
    tree_sha = _raw_object(bare, "tree", tree_body)
    branch_ref = _git("--git-dir", str(bare), "symbolic-ref", "HEAD")
    commit_body = (
        f"tree {tree_sha}\nauthor Runtime Fixture <fixture@example.test> 1760000000 +0000\n"
        "committer Runtime Fixture <fixture@example.test> 1760000000 +0000\n\nraw fixture\n"
    ).encode("ascii")
    commit_sha = _raw_object(bare, "commit", commit_body)
    _git("--git-dir", str(bare), "update-ref", branch_ref, commit_sha)


def _push_index_blob(bare: Path, content: str, mode: str, name: str) -> None:
    blob = _raw_object(bare, "blob", content.encode("utf-8"))
    base_blob = _git("--git-dir", str(bare), "rev-parse", "HEAD:README.txt")
    entries = [
        (b"README.txt", b"100644", base_blob),
        (os.fsencode(name), mode.encode("ascii"), blob),
    ]
    tree_body = b"".join(
        entry_mode + b" " + entry_name + b"\0" + bytes.fromhex(sha)
        for entry_name, entry_mode, sha in sorted(entries, key=lambda entry: entry[0])
    )
    _publish_raw_tree(bare, tree_body)


def _publish_long_path(bare: Path, parts: list[str], content: str) -> None:
    blob = _raw_object(bare, "blob", content.encode("utf-8"))
    tree_sha = _raw_object(bare, "tree", b"100644 file.txt\0" + bytes.fromhex(blob))
    for component in reversed(parts):
        tree_sha = _raw_object(
            bare, "tree", b"40000 " + os.fsencode(component) + b"\0" + bytes.fromhex(tree_sha)
        )
    branch_ref = _git("--git-dir", str(bare), "symbolic-ref", "HEAD")
    commit_body = (
        f"tree {tree_sha}\nauthor Runtime Fixture <fixture@example.test> 1760000000 +0000\n"
        "committer Runtime Fixture <fixture@example.test> 1760000000 +0000\n\nlong path fixture\n"
    ).encode("ascii")
    _git("--git-dir", str(bare), "update-ref", branch_ref, _raw_object(bare, "commit", commit_body))


def _run_fixture_import(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    bare: Path,
    *,
    max_bytes: int = 524_288_000,
    max_files: int = 50_000,
) -> tuple[dict[str, object], Path]:
    service, repository = _service(tmp_path, monkeypatch, max_bytes=max_bytes, max_files=max_files)
    try:
        service.start_worker()
        preview = service.preview("session", bare.as_uri(), None)
        job = service.start("session", str(preview["preview_id"]), "Fixture")
        result = _wait_for_job(service, str(job["job_id"]))
        return result, service.managed_directory / str(job["job_id"])
    finally:
        service.stop_worker()
        repository.close()


def _service(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    max_bytes: int = 524_288_000,
    max_files: int = 50_000,
    timeout: int = 20,
    process_factory=subprocess.Popen,
) -> tuple[GitHubImportService, SQLiteRepository]:
    monkeypatch.setenv("CHINESCAN_TEST_GITHUB_IMPORT", "1")
    tmp_path.mkdir(parents=True, exist_ok=True)
    database = tmp_path / "private" / "records.sqlite3"
    repository = SQLiteRepository(database)
    settings = Settings(
        _env_file=None,
        database_path=database,
        reports_dir=tmp_path / "private" / "reports",
        github_import_enabled=True,
        github_import_timeout_seconds=timeout,
        github_import_max_bytes=max_bytes,
        github_import_max_files=max_files,
    )
    service = GitHubImportService(
        repository,
        settings,
        tmp_path / "managed-imports",
        test_file_transport=True,
        process_factory=process_factory,
    )
    return service, repository


def _wait_for_job(service: GitHubImportService, job_id: str, session_id: str = "session"):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        state = service.get(session_id, job_id)
        if state["status"] in {"succeeded", "failed", "cancelled", "incomplete"}:
            return state
        time.sleep(0.05)
    pytest.fail("GitHub import job did not reach a terminal state within 15 seconds.")


def _api_client(tmp_path: Path, *, test_file_transport: bool = False):
    private = tmp_path / "api-private"
    private.mkdir()
    database = private / "records.sqlite3"
    credentials = private / "operator.json"
    create_operator(credentials, "github@example.test", "github-import-test-password-123")
    settings = Settings(
        _env_file=None,
        database_path=database,
        reports_dir=private / "reports",
        github_import_enabled=True,
    )
    application = create_app(
        database,
        credentials,
        settings=settings,
        serve_frontend=False,
        github_import_test_file_transport=test_file_transport,
    )
    client = TestClient(application, base_url="http://127.0.0.1", client=("127.0.0.1", 50143))
    login = client.post(
        "/api/auth/login",
        json={"email": "github@example.test", "password": "github-import-test-password-123"},
        headers={"Origin": "http://127.0.0.1"},
    )
    assert login.status_code == 200
    headers = {"Origin": "http://127.0.0.1", "X-CSRF-Token": login.json()["csrf_token"]}
    return application, client, headers


@pytest.mark.parametrize(
    "value",
    [
        "https://github.com/owner/repo",
        "https://github.com/owner/repo.git",
        "https://github.com/owner/repo/",
        "https://github.com/a-b/r._-",
    ],
)
def test_github_url_accepts_supported_forms(value: str) -> None:
    assert validate_github_url(value).canonical_url.startswith("https://github.com/")


@pytest.mark.parametrize(
    "value",
    [
        "http://github.com/o/r",
        "https://www.github.com/o/r",
        "https://github.com.evil.test/o/r",
        "ssh://github.com/o/r",
        "git@github.com:o/r",
        "file://github.com/o/r",
        "https://user:pass@github.com/o/r",
        "https://github.com:443/o/r",
        "https://github.com/o/r?x=y",
        "https://github.com/o/r#frag",
        "https://github.com/o%2fr/r",
        "https://github.com/o/r%2e",
        "https://github.com/o/r/tree/main",
        "https://github.com/-owner/r",
        "https://github.com/owner-/r",
        "https://github.com/owner/.",
        "https://github.com/owner/..",
        "https://github.com/ownеr/repo",
        "https://github.com/o/r\\x",
        "https://github.com/o/r\n",
        "https://github.com/" + "a" * 301,
    ],
)
def test_github_url_rejects_unsafe_or_malformed_forms(value: str) -> None:
    with pytest.raises(GitHubImportError):
        validate_github_url(value)


@pytest.mark.parametrize("value", [None, "main", "release/1.0", "f" * 40])
def test_ref_accepts_branch_tag_and_full_sha(value: str | None) -> None:
    assert validate_ref(value) == (value.lower() if value and len(value) == 40 else value)


@pytest.mark.parametrize(
    "value",
    ["", "../main", "a..b", "-branch", "/main", "main/", "topic.lock", "x@{y", "x y", "é"],
)
def test_ref_rejects_git_metacharacters_and_non_ascii(value: str) -> None:
    with pytest.raises(GitHubImportError):
        validate_ref(value)


def test_disabled_cli_and_api_use_same_stable_code(tmp_path) -> None:
    config = tmp_path / "isolated.toml"
    config.write_text("github_import_enabled = false\n", encoding="utf-8")
    result = CliRunner().invoke(
        app,
        ["--config", str(config), "github", "preview", "https://github.com/a/b", "--json"],
    )
    assert result.exit_code == 2
    assert '"code": "feature_disabled"' in result.output


def test_clone_argv_and_scrubbed_environment_are_exact(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("PATH", os.environ["PATH"])
    monkeypatch.setenv("GIT_ASKPASS", "runtime-secret-shaped-fixture")
    monkeypatch.setenv("SSH_AUTH_SOCK", "runtime-agent-fixture")
    monkeypatch.setenv("GH_TOKEN", "runtime-token-fixture")
    monkeypatch.setenv("CHINESCAN_TEST_GITHUB_IMPORT", "1")
    hooks = tmp_path / "empty-hooks"
    target = tmp_path / "target"
    argv = build_clone_argv("https://github.com/example/repo", target, hooks)
    expected = [
        "--depth",
        "1",
        "--single-branch",
        "--no-tags",
        "--no-recurse-submodules",
        "--filter=blob:limit=16m",
    ]
    for flag in expected:
        assert flag in argv
    for key in ("GIT_ASKPASS", "SSH_AUTH_SOCK", "GH_TOKEN"):
        assert key not in build_git_environment()
    assert set(build_git_environment()) == {
        "PATH",
        "GIT_TERMINAL_PROMPT",
        "GIT_LFS_SKIP_SMUDGE",
        "GIT_CONFIG_NOSYSTEM",
        "GIT_CONFIG_GLOBAL",
        "GIT_ALLOW_PROTOCOL",
    }
    assert build_git_environment()["GIT_ALLOW_PROTOCOL"] == "https"
    assert build_git_environment()["GIT_CONFIG_GLOBAL"] == (
        "NUL" if os.name == "nt" else os.devnull
    )
    assert (
        argv[0] == "git"
        and "protocol.allow=never" in argv
        and "protocol.https.allow=always" in argv
    )
    assert f"core.hooksPath={hooks}" in argv
    assert "core.symlinks=false" in argv and "core.fsmonitor=false" in argv
    assert "credential.helper=" in argv and "http.followRedirects=false" in argv


def test_test_only_file_transport_is_refused_without_test_guard(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("CHINESCAN_TEST_GITHUB_IMPORT", raising=False)
    with pytest.raises(GitHubImportError, match="guarded tests"):
        build_git_environment(test_file_transport=True)
    with pytest.raises(GitHubImportError, match="invalid|Use an https"):
        validate_github_url((tmp_path / "private.git").as_uri())


def test_preview_is_network_free_session_bound_expiring_and_single_use(
    tmp_path, monkeypatch
) -> None:
    bare = _bare_repo(tmp_path)
    calls: list[list[str]] = []

    def forbidden_process(*args, **kwargs):
        calls.append(list(args[0]))
        raise AssertionError("preview must not start a subprocess")

    service, repository = _service(tmp_path, monkeypatch, process_factory=forbidden_process)
    preview = service.preview("session-a", bare.as_uri(), "main")
    assert preview["fetch_depth"] == 1
    assert preview["submodules"] is False and preview["lfs"] is False
    assert preview["url"] == "https://github.com/test-fixture/repository"
    assert str(tmp_path) not in str(preview)
    assert calls == []
    with pytest.raises(GitHubImportError, match="not available"):
        service.start("session-b", str(preview["preview_id"]), "Fixture")
    job = service.start("session-a", str(preview["preview_id"]), "Fixture")
    with pytest.raises(GitHubImportError, match="already been used"):
        service.start("session-a", str(preview["preview_id"]), "Fixture")
    stored_preview = service._previews[str(preview["preview_id"])]
    stored_preview.expires_at = time.monotonic() - 1
    expired = service.preview("session-a", bare.as_uri(), None)
    service._previews[str(expired["preview_id"])].expires_at = time.monotonic() - 1
    with pytest.raises(GitHubImportError, match="expired"):
        service.start("session-a", str(expired["preview_id"]), "Fixture")
    assert job["status"] == "queued"
    repository.close()


def test_local_bare_repository_import_verifies_sha_and_removes_git(tmp_path, monkeypatch) -> None:
    content = b"static fixture content\n"
    short_tmp_path = _windows_short_path(tmp_path)
    assert str(short_tmp_path).casefold() != str(tmp_path).casefold()
    bare = _bare_repo(short_tmp_path, {"README.txt": content.decode("ascii")})
    expected_sha = _git("--git-dir", str(bare), "rev-parse", "HEAD")
    service, repository = _service(short_tmp_path, monkeypatch, max_bytes=len(content) + 8)
    canary = short_tmp_path / "hook-ran.txt"
    hook_dir = bare / "hooks"
    hook_dir.mkdir(exist_ok=True)
    (hook_dir / "post-checkout").write_text(
        f"#!/bin/sh\nprintf canary > '{canary}'\n", encoding="utf-8"
    )
    try:
        service.start_worker()
        preview = service.preview("session", bare.as_uri(), None)
        job = service.start("session", str(preview["preview_id"]), "Fixture")
        result = _wait_for_job(service, str(job["job_id"]))
        assert result["status"] == "succeeded", result
        assert result["commit_sha"] == expected_sha
        assert result["fetched_at"]
        assert result["file_count"] == 1
        assert result["total_bytes"] == len(content)
        imported_path = service.managed_directory / str(job["job_id"])
        assert imported_path.is_dir()
        assert not (imported_path / ".git").exists()
        assert not canary.exists()
        assert str(service.managed_directory) not in str(result)
        audit_events = [item["event"] for item in repository.list_records("github_import_audit")]
        assert {"preview", "start", "running", "finish"}.issubset(set(audit_events))
    finally:
        service.stop_worker()
        repository.close()


def test_api_preview_then_import_job_is_session_bound_and_path_free(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("CHINESCAN_TEST_GITHUB_IMPORT", "1")
    bare = _bare_repo(tmp_path)
    application, client, headers = _api_client(tmp_path, test_file_transport=True)
    manager = application.state.github_import_manager
    manager.start_worker()
    calls: list[str] = []

    def forbidden_process(*args, **kwargs):
        calls.append(str(args[0][0]))
        raise AssertionError("preview must not invoke Git")

    manager.process_factory = forbidden_process
    try:
        preview_response = client.post(
            "/api/github/previews", json={"url": bare.as_uri()}, headers=headers
        )
        assert preview_response.status_code == 200, preview_response.text
        preview = preview_response.json()
        assert preview["url"] == "https://github.com/test-fixture/repository"
        assert str(tmp_path) not in preview_response.text
        assert preview["fetch_depth"] == 1
        assert preview["max_bytes"] == 524_288_000
        assert preview["git_metadata_allowance_bytes"] > 0
        assert calls == []

        # A separate authenticated session cannot consume the first session's preview.
        other = TestClient(application, base_url="http://127.0.0.1", client=("127.0.0.1", 50144))
        second_login = other.post(
            "/api/auth/login",
            json={"email": "github@example.test", "password": "github-import-test-password-123"},
            headers={"Origin": "http://127.0.0.1"},
        )
        assert second_login.status_code == 200
        other_headers = {
            "Origin": "http://127.0.0.1",
            "X-CSRF-Token": second_login.json()["csrf_token"],
        }
        forbidden = other.post(
            "/api/github/imports",
            json={"preview_id": preview["preview_id"], "name": "Fixture"},
            headers=other_headers,
        )
        assert forbidden.status_code == 409
        assert forbidden.json()["detail"]["code"] == "preview_unavailable"
        other.close()

        manager.process_factory = subprocess.Popen
        imported = client.post(
            "/api/github/imports",
            json={"preview_id": preview["preview_id"], "name": "Fixture"},
            headers=headers,
        )
        assert imported.status_code == 202, imported.text
        job_id = imported.json()["job_id"]
        terminal = None
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            current = client.get(f"/api/github/imports/{job_id}")
            assert current.status_code == 200, current.text
            if current.json()["status"] in {"succeeded", "failed", "cancelled", "incomplete"}:
                terminal = current.json()
                break
            time.sleep(0.1)
        assert terminal is not None
        assert terminal["status"] == "succeeded", terminal
        assert str(tmp_path) not in current.text
    finally:
        manager.stop_worker()
        client.close()


def test_github_api_origin_csrf_auth_and_rate_limit(tmp_path, monkeypatch) -> None:
    application, client, headers = _api_client(tmp_path)
    try:
        no_origin = client.post("/api/github/previews", json={"url": "https://github.com/a/b"})
        assert no_origin.status_code == 403
        no_csrf = client.post(
            "/api/github/previews",
            json={"url": "https://github.com/a/b"},
            headers={"Origin": "http://127.0.0.1"},
        )
        assert no_csrf.status_code == 403
        wrong_origin = client.post(
            "/api/github/previews",
            json={"url": "https://github.com/a/b"},
            headers={**headers, "Origin": "http://localhost:9999"},
        )
        assert wrong_origin.status_code == 403
        anonymous = TestClient(
            application, base_url="http://127.0.0.1", client=("127.0.0.1", 50145)
        )
        anonymous_response = anonymous.get("/api/github/imports/unknown")
        assert anonymous_response.status_code in {401, 403}
        for _ in range(10):
            response = client.post(
                "/api/github/previews", json={"url": "https://github.com/a/b"}, headers=headers
            )
            assert response.status_code == 200
        limited = client.post(
            "/api/github/previews", json={"url": "https://github.com/a/b"}, headers=headers
        )
        assert limited.status_code == 429
        assert limited.json()["detail"]["code"] == "rate_limited"
    finally:
        client.close()


def test_cli_import_requires_yes_after_printing_path_free_preview(tmp_path) -> None:
    config = tmp_path / "github-enabled.toml"
    database = tmp_path / "cli-records.sqlite3"
    config.write_text(
        f'github_import_enabled = true\ndatabase_path = "{database.as_posix()}"\n',
        encoding="utf-8",
    )
    result = CliRunner().invoke(
        app,
        [
            "--config",
            str(config),
            "github",
            "import",
            "https://github.com/example/repo",
            "--name",
            "Fixture",
            "--ref",
            "main",
            "--json",
        ],
    )
    assert result.exit_code == 2
    assert '"url": "https://github.com/example/repo"' in result.output
    assert "Import not started. Re-run with --yes to confirm." in result.output
    assert str(tmp_path) not in result.output


def test_cli_preview_matches_api_canonical_url_and_ref(tmp_path) -> None:
    config = tmp_path / "github-enabled.toml"
    config.write_text("github_import_enabled = true\n", encoding="utf-8")
    cli = CliRunner().invoke(
        app,
        [
            "--config",
            str(config),
            "--database",
            str(tmp_path / "cli.sqlite3"),
            "github",
            "preview",
            "https://github.com/example/repo.git/",
            "--ref",
            "release/1",
            "--json",
        ],
    )
    assert cli.exit_code == 0, cli.output
    cli_payload = __import__("json").loads(cli.stdout)
    assert cli_payload["url"] == "https://github.com/example/repo"
    assert cli_payload["ref"] == "release/1"


def test_committed_symlink_is_neutralized_by_core_symlinks_false(tmp_path, monkeypatch) -> None:
    bare = _bare_repo(tmp_path)
    _push_index_blob(bare, "outside-target.txt", "120000", "link.txt")
    result, imported = _run_fixture_import(tmp_path, monkeypatch, bare)
    assert result["status"] == "succeeded", result
    assert not (imported / "link.txt").is_symlink()
    assert (imported / "link.txt").read_text(encoding="utf-8") == "outside-target.txt"
    assert not (imported / ".git").exists()


def test_pinned_sha_uses_shallow_fetch_and_records_exact_commit(tmp_path, monkeypatch) -> None:
    bare = _bare_repo(tmp_path)
    sha = _git("--git-dir", str(bare), "rev-parse", "HEAD")
    service, repository = _service(tmp_path / "import", monkeypatch)
    git_calls: list[list[str]] = []
    original_factory = service.process_factory

    def record_process(argv, **kwargs):
        git_calls.append(list(argv))
        return original_factory(argv, **kwargs)

    service.process_factory = record_process
    try:
        service.start_worker()
        preview = service.preview("session", bare.as_uri(), sha)
        job = service.start("session", str(preview["preview_id"]), "Pinned")
        result = _wait_for_job(service, str(job["job_id"]))
        assert result["status"] == "succeeded", result
        assert result["commit_sha"] == sha
        fetch = next(argv for argv in git_calls if "fetch" in argv)
        assert "--depth" in fetch and "1" in fetch
        assert "--recurse-submodules=no" in fetch
        assert sha in fetch
    finally:
        service.stop_worker()
        repository.close()


def test_submodule_entry_is_not_fetched_and_lfs_pointer_is_not_smudged(
    tmp_path, monkeypatch
) -> None:
    submodule = _bare_repo(tmp_path / "submodule", {"private.txt": "submodule bytes"})
    submodule_sha = _git("--git-dir", str(submodule), "rev-parse", "HEAD")
    bare = _bare_repo(tmp_path / "parent")
    work = bare.parent / "work"
    lfs_pointer = (
        "version https://git-lfs.github.com/spec/v1\noid sha256:" + "a" * 64 + "\nsize 8\n"
    )
    (work / "asset.bin").write_text(lfs_pointer, encoding="ascii")
    (work / ".gitmodules").write_text(
        f'[submodule "nested"]\n\tpath = nested\n\turl = {submodule.as_uri()}\n',
        encoding="utf-8",
    )
    _git("add", ".gitmodules", "asset.bin", cwd=work)
    _git("commit", "-m", "runtime submodule and LFS pointer", cwd=work)
    _git(
        "push", str(bare), "HEAD:refs/heads/" + _git("branch", "--show-current", cwd=work), cwd=work
    )
    _git("update-index", "--add", "--cacheinfo", "160000", submodule_sha, "nested", cwd=work)
    _git("commit", "-m", "runtime gitlink", cwd=work)
    _git(
        "push", str(bare), "HEAD:refs/heads/" + _git("branch", "--show-current", cwd=work), cwd=work
    )
    result, imported = _run_fixture_import(tmp_path / "import", monkeypatch, bare)
    assert result["status"] == "succeeded", result
    assert (imported / "asset.bin").read_text(encoding="ascii") == lfs_pointer
    assert not (imported / "nested" / "private.txt").exists()
    assert result["file_count"] == 3


@pytest.mark.parametrize(
    ("files", "max_bytes", "max_files"),
    [
        ({"README.txt": "base", "large.bin": "x" * 8192}, 128, 50_000),
        ({"README.txt": "base", "one.txt": "1", "two.txt": "2"}, 1024, 2),
    ],
)
def test_oversized_and_too_many_project_files_fail_quota(
    tmp_path, monkeypatch, files, max_bytes, max_files
) -> None:
    bare = _bare_repo(tmp_path, files)
    result, imported = _run_fixture_import(
        tmp_path / "import", monkeypatch, bare, max_bytes=max_bytes, max_files=max_files
    )
    assert result["status"] == "failed", result
    assert result["error_code"] == "quota_exceeded"
    assert not imported.exists()


@pytest.mark.parametrize("unsafe_name", ["CON", "trailing.", "ads:stream"])
def test_windows_reserved_trailing_and_ads_names_are_rejected(
    tmp_path, monkeypatch, unsafe_name: str
) -> None:
    bare = _bare_repo(tmp_path, {"README.txt": "base"})
    _push_index_blob(bare, "unsafe", "100644", unsafe_name)
    result, imported = _run_fixture_import(tmp_path / "import", monkeypatch, bare)
    assert result["status"] == "failed", result
    assert result["error_code"] == "unsafe_entries"
    assert not imported.exists()


def test_overlong_repository_path_is_rejected(tmp_path, monkeypatch) -> None:
    bare = _bare_repo(tmp_path, {"README.txt": "base"})
    parts = ["segment-" + "x" * 24 for _ in range(8)] + ["file.txt"]
    _publish_long_path(bare, parts, "long path")
    result, imported = _run_fixture_import(tmp_path / "import", monkeypatch, bare)
    assert result["status"] == "failed", result
    assert result["error_code"] == "unsafe_entries"
    assert not imported.exists()


@pytest.mark.parametrize("terminal_action", ["timeout", "cancel", "quota", "file_count"])
def test_timeout_cancel_and_quota_terminate_the_started_process(
    tmp_path, monkeypatch, terminal_action: str
) -> None:
    bare = _bare_repo(tmp_path)
    started = threading.Event()
    processes: list[subprocess.Popen[bytes]] = []

    def sleeping_process_factory(*args, **kwargs):
        argv = args[0]
        if terminal_action in {"quota", "file_count"}:
            clone_target = Path(argv[-1])
            clone_target.mkdir(parents=True, exist_ok=True)
            if terminal_action == "quota":
                (clone_target / "oversized.bin").write_bytes(b"x" * 128)
            else:
                for index in range(3):
                    (clone_target / f"file-{index}.txt").write_text("x", encoding="utf-8")
        process = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            **kwargs,
        )
        processes.append(process)
        started.set()
        return process

    service, repository = _service(
        tmp_path / "import",
        monkeypatch,
        timeout=1 if terminal_action == "timeout" else 20,
        max_bytes=16 if terminal_action == "quota" else 524_288_000,
        max_files=2 if terminal_action == "file_count" else 50_000,
        process_factory=sleeping_process_factory,
    )
    try:
        service.start_worker()
        preview = service.preview("session", bare.as_uri(), None)
        job = service.start("session", str(preview["preview_id"]), "Fixture")
        assert started.wait(5)
        if terminal_action == "cancel":
            service.cancel("session", str(job["job_id"]))
        result = _wait_for_job(service, str(job["job_id"]))
        expected = {
            "timeout": ("failed", "timeout"),
            "cancel": ("cancelled", "cancelled"),
            "quota": ("failed", "quota_exceeded"),
            "file_count": ("failed", "quota_exceeded"),
        }
        assert (result["status"], result["error_code"]) == expected[terminal_action]
        assert processes and all(process.poll() is not None for process in processes)
    finally:
        service.stop_worker()
        repository.close()


def test_import_queue_is_bounded_without_starting_more_than_one_worker(
    tmp_path, monkeypatch
) -> None:
    bare = _bare_repo(tmp_path)
    service, repository = _service(tmp_path / "import", monkeypatch)
    try:
        queued = []
        for index in range(service.QUEUE_CAPACITY):
            preview = service.preview("session", bare.as_uri(), None)
            queued.append(service.start("session", str(preview["preview_id"]), f"Fixture {index}"))
        assert all(job["status"] == "queued" for job in queued)
        preview = service.preview("session", bare.as_uri(), None)
        with pytest.raises(GitHubImportError, match="queue is full"):
            service.start("session", str(preview["preview_id"]), "Overflow")
        assert service._worker is None
    finally:
        repository.close()


def test_poisoned_clone_path_cleanup_refuses_outside_directory(tmp_path, monkeypatch) -> None:
    bare = _bare_repo(tmp_path)
    service, repository = _service(tmp_path / "import", monkeypatch)
    outside = tmp_path / "outside"
    outside.mkdir()
    canary = outside / "keep.txt"
    canary.write_text("untouched", encoding="utf-8")
    try:
        preview = service.preview("session", bare.as_uri(), None)
        job = service.start("session", str(preview["preview_id"]), "Fixture")
        private_job = service._jobs[str(job["job_id"])]
        private_job.clone_path = outside
        service._cleanup_job_clone(private_job)
        assert canary.read_text(encoding="utf-8") == "untouched"
        assert outside.is_dir()
    finally:
        repository.close()


def test_git_stderr_canary_and_internal_path_never_escape_error_or_logs(
    tmp_path, monkeypatch, caplog
) -> None:
    bare = _bare_repo(tmp_path)
    canary = f"stderr-canary-{tmp_path}"

    class FailedProcess:
        pid = 1
        returncode = 1

        def __init__(self) -> None:
            self.stderr = io.BytesIO(canary.encode("utf-8"))

        def poll(self) -> int:
            return 1

        def wait(self, timeout: float | None = None) -> int:
            del timeout
            return 1

    def failed_process_factory(*args, **kwargs) -> FailedProcess:
        del args, kwargs
        return FailedProcess()

    service, repository = _service(
        tmp_path / "import", monkeypatch, process_factory=failed_process_factory
    )
    try:
        service.start_worker()
        preview = service.preview("session", bare.as_uri(), None)
        job = service.start("session", str(preview["preview_id"]), "Fixture")
        result = _wait_for_job(service, str(job["job_id"]))
        assert result["status"] == "failed"
        assert result["error_code"] == "network_unreachable"
        assert canary not in repr(result)
        assert str(tmp_path) not in repr(result)
        assert canary not in caplog.text
        assert str(tmp_path) not in caplog.text
    finally:
        service.stop_worker()
        repository.close()


def test_reparse_entry_and_outside_root_resolution_are_rejected(tmp_path, monkeypatch) -> None:
    service, repository = _service(tmp_path, monkeypatch)
    service.managed_directory.mkdir(parents=True)
    root = service.managed_directory / "runtime-clone"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "canary.txt").write_text("outside", encoding="utf-8")
    junction = root / "linked-directory"
    os.symlink(outside, junction, target_is_directory=True)
    try:
        with pytest.raises(GitHubImportError, match="link or reparse point"):
            service._verify_tree(root)

        original_link_check = github_import_core._is_link_or_reparse
        monkeypatch.setattr(
            github_import_core,
            "_is_link_or_reparse",
            lambda path, metadata: (
                False if path == junction else original_link_check(path, metadata)
            ),
        )
        with pytest.raises(GitHubImportError, match="outside the import"):
            service._verify_tree(root)
        assert (outside / "canary.txt").read_text(encoding="utf-8") == "outside"
    finally:
        repository.close()


def test_ads_is_detected_and_incomplete_when_a_tracked_file_vanishes(tmp_path, monkeypatch) -> None:
    service, repository = _service(tmp_path, monkeypatch)
    service.managed_directory.mkdir(parents=True)
    clone = service.managed_directory / "ads-clone"
    clone.mkdir()
    file_path = clone / "ordinary.txt"
    file_path.write_text("ordinary", encoding="utf-8")
    stream_path = Path(str(file_path) + ":runtime-stream")
    stream_path.write_text("stream", encoding="utf-8")
    try:
        with pytest.raises(GitHubImportError, match="alternate data stream"):
            service._verify_tree(clone)
    finally:
        stream_path.unlink(missing_ok=True)
        repository.close()

    bare = _bare_repo(tmp_path / "vanishing")
    service, repository = _service(tmp_path / "verify", monkeypatch)
    original_verify_tree = service._verify_tree

    def file_vanishes_after_walk(root):
        measured = original_verify_tree(root)
        (root / "README.txt").unlink()
        size, count, metadata_bytes, found = measured
        found.discard("readme.txt")
        return size, count, metadata_bytes, found

    monkeypatch.setattr(service, "_verify_tree", file_vanishes_after_walk)
    try:
        service.start_worker()
        preview = service.preview("session", bare.as_uri(), None)
        job = service.start("session", str(preview["preview_id"]), "Vanish")
        result = _wait_for_job(service, str(job["job_id"]))
        assert result["status"] == "incomplete"
        assert result["error_code"] == "quarantined_or_missing_files"
    finally:
        service.stop_worker()
        repository.close()
