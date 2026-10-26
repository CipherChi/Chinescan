"""Strict hostname and explicit-authorization validation for domain assessments."""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

MAX_AUTH_FILE_BYTES = 64_000
_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.I)


class AuthorizationError(ValueError):
    """The target or authorization evidence is invalid or insufficient."""


@dataclass(frozen=True)
class AuthorizationGrant:
    target: str
    method: str
    operator: str
    authorized_at: datetime
    valid_until: datetime | None
    profile: str


def normalize_hostname(value: str) -> str:
    """Normalize a fully qualified DNS hostname, rejecting URLs and IP literals."""
    raw = value.strip()
    if not raw or any(char in raw for char in "/\\@?#:") or raw.startswith("."):
        raise AuthorizationError("target must be a hostname, not a URL or address")
    candidate = raw.rstrip(".")
    try:
        ipaddress.ip_address(candidate)
        raise AuthorizationError("IP literals are not accepted as domain targets")
    except ValueError as exc:
        if isinstance(exc, AuthorizationError):
            raise
    try:
        hostname = candidate.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise AuthorizationError("target hostname is not valid IDNA") from exc
    labels = hostname.split(".")
    if (
        len(hostname) > 253
        or len(labels) < 2
        or any(not _LABEL.fullmatch(label) for label in labels)
    ):
        raise AuthorizationError("target must be a valid fully qualified hostname")
    if hostname == "localhost" or hostname.endswith((".localhost", ".local", ".internal")):
        raise AuthorizationError("local and internal hostnames are outside this assessment profile")
    return hostname


def authorize_target(
    target: str,
    *,
    profile: str,
    operator: str | None,
    assert_ownership: bool,
    authorization_file: Path | None,
    now: datetime | None = None,
) -> AuthorizationGrant:
    """Validate the explicit ownership assertion or exact-scope authorization JSON."""
    hostname = normalize_hostname(target)
    if profile not in {"light", "deep"}:
        raise AuthorizationError("profile must be light or deep")
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        raise AuthorizationError("authorization time must include a timezone")
    if assert_ownership == (authorization_file is not None):
        raise AuthorizationError(
            "provide exactly one of --i-own-this-target or --authorization-file"
        )

    if assert_ownership:
        identity = (operator or "").strip()
        if not identity:
            raise AuthorizationError("--i-own-this-target requires --operator")
        return AuthorizationGrant(
            hostname, "ownership_assertion", identity[:100], current, None, profile
        )

    if authorization_file is None:
        raise AuthorizationError("authorization file was not provided")
    if authorization_file.is_symlink() or not authorization_file.is_file():
        raise AuthorizationError("authorization file must be a local regular file")
    try:
        if authorization_file.stat().st_size > MAX_AUTH_FILE_BYTES:
            raise AuthorizationError("authorization file exceeds the size limit")
        document = json.loads(authorization_file.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AuthorizationError("authorization file could not be read as valid JSON") from exc
    if not isinstance(document, dict):
        raise AuthorizationError("authorization file must contain a JSON object")
    try:
        scope = normalize_hostname(str(document["target"]))
        granted_operator = str(document["granted_by"]).strip()
        valid_from = _parse_time(document["valid_from"])
        valid_until = _parse_time(document["valid_until"]) if document.get("valid_until") else None
        authorized_profile = str(document.get("profile", "light"))
    except (KeyError, TypeError, ValueError) as exc:
        raise AuthorizationError(
            "authorization file is missing valid scope or grant fields"
        ) from exc
    if scope != hostname:
        raise AuthorizationError("authorization scope must exactly match the requested hostname")
    if not granted_operator:
        raise AuthorizationError("authorization file must identify the granting operator")
    if authorized_profile not in {"light", "deep"} or authorized_profile != profile:
        raise AuthorizationError("requested profile does not match the authorization profile")
    if valid_from > current or (valid_until is not None and valid_until < current):
        raise AuthorizationError("authorization is outside its validity window")
    if valid_until is not None and valid_until < valid_from:
        raise AuthorizationError("authorization expiry precedes its start time")
    return AuthorizationGrant(
        hostname,
        "authorization_file",
        granted_operator[:100],
        current,
        valid_until,
        profile,
    )


def _parse_time(value: object) -> datetime:
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("authorization timestamp needs timezone")
    return parsed.astimezone(UTC)
