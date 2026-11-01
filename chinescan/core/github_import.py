"""Pure validation and safe public GitHub source normalization."""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit


class GitHubImportError(ValueError):
    """Validation error with a stable, user-safe code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


_OWNER = re.compile(r"[A-Za-z0-9-]{1,39}\Z", re.ASCII)
_REPO = re.compile(r"[A-Za-z0-9._-]{1,100}\Z", re.ASCII)
_REF = re.compile(r"[A-Za-z0-9._/-]{1,100}\Z", re.ASCII)
_SHA = re.compile(r"[0-9A-Fa-f]{40}\Z", re.ASCII)


@dataclass(frozen=True, slots=True)
class ValidatedSource:
    canonical_url: str
    owner: str
    repo: str


def validate_github_url(value: str) -> ValidatedSource:
    """Accept only a plain public github.com repository URL."""
    if not isinstance(value, str) or not 1 <= len(value) <= 300:
        raise GitHubImportError("invalid_url", "Enter a valid GitHub repository URL.")
    if not value.isascii() or any(ord(char) < 33 or ord(char) == 127 for char in value):
        raise GitHubImportError("invalid_url", "The repository URL must contain plain ASCII only.")
    if "\\" in value or re.search(r"%(?:2f|2e)", value, re.IGNORECASE):
        raise GitHubImportError("invalid_url", "Encoded path separators and dots are not allowed.")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise GitHubImportError("invalid_url", "Enter a valid GitHub repository URL.") from exc
    if (
        parsed.scheme != "https"
        or parsed.netloc != "github.com"
        or port is not None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise GitHubImportError(
            "invalid_url", "Use an https://github.com repository URL without query or fragment."
        )
    match = re.fullmatch(
        r"/([A-Za-z0-9-]{1,39})/([A-Za-z0-9._-]{1,100})(?:\.git)?/?", parsed.path, re.ASCII
    )
    if match is None:
        raise GitHubImportError("invalid_url", "Use exactly https://github.com/<owner>/<repo>.")
    owner, repo = match.groups()
    if not _OWNER.fullmatch(owner) or owner.startswith("-") or owner.endswith("-"):
        raise GitHubImportError("invalid_url", "The repository owner is invalid.")
    if not _REPO.fullmatch(repo) or repo in {".", ".."}:
        raise GitHubImportError("invalid_url", "The repository name is invalid.")
    return ValidatedSource(f"https://github.com/{owner}/{repo}", owner, repo)


def validate_ref(value: str | None) -> str | None:
    """Validate a branch, tag, or full commit SHA without invoking Git."""
    if value is None:
        return None
    if not isinstance(value, str) or not 1 <= len(value) <= 100 or not value.isascii():
        raise GitHubImportError("invalid_ref", "The branch, tag, or commit reference is invalid.")
    if _SHA.fullmatch(value):
        return value.lower()
    if (
        not _REF.fullmatch(value)
        or ".." in value
        or value.startswith(("-", "/"))
        or value.endswith(("/", ".lock"))
        or "@{" in value
        or any(part in {"", "."} for part in value.split("/"))
    ):
        raise GitHubImportError("invalid_ref", "The branch, tag, or commit reference is invalid.")
    return value
