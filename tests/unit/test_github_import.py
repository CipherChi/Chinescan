"""GitHub source validation tests; fixtures are constructed from runtime strings."""

import pytest
from typer.testing import CliRunner

from chinescan.cli.app import app
from chinescan.core.github_import import GitHubImportError, validate_github_url, validate_ref


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
