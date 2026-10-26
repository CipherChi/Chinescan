"""Single-operator credentials and process-local opaque sessions."""

from __future__ import annotations

import hashlib
import json
import secrets
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError


class CredentialError(ValueError):
    """Credential file is missing or invalid."""


class LoginThrottle:
    """Per-process IP throttling for the one local login endpoint."""

    def __init__(self, limit: int = 5, window_seconds: int = 60) -> None:
        self.limit = limit
        self.window_seconds = window_seconds
        self._failures: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def allowed(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            recent = [
                stamp for stamp in self._failures.get(key, []) if now - stamp < self.window_seconds
            ]
            if len(recent) >= self.limit:
                self._failures[key] = recent
                return False
            recent.append(now)
            self._failures[key] = recent
            return True

    def succeeded(self, key: str) -> None:
        with self._lock:
            self._failures.pop(key, None)


def create_operator(path: Path, username: str, password: str) -> None:
    """Create one Argon2id operator record without overwriting an existing account."""
    if not username or len(username) > 100:
        raise CredentialError("Username must be between 1 and 100 characters.")
    if len(password) < 12 or len(password) > 1024:
        raise CredentialError("Password must be between 12 and 1024 characters.")
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(
        {"username": username, "password_hash": PasswordHasher().hash(password)},
        separators=(",", ":"),
    )
    try:
        with path.open("x", encoding="utf-8") as stream:
            stream.write(payload)
            stream.flush()
    except FileExistsError as exc:
        raise CredentialError(
            "An operator account already exists; refusing to replace it."
        ) from exc
    try:
        path.chmod(0o600)
    except OSError:
        # Windows access is controlled by the containing user's profile ACL, not POSIX bits.
        pass


def verify_operator(path: Path, username: str, password: str) -> bool:
    try:
        data: Any = json.loads(path.read_text(encoding="utf-8"))
        stored_user = data["username"]
        password_hash = data["password_hash"]
        if not isinstance(stored_user, str) or not isinstance(password_hash, str):
            raise ValueError
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise CredentialError("Local operator account is unavailable or invalid.") from exc
    try:
        password_matches = PasswordHasher().verify(password_hash, password)
        username_matches = secrets.compare_digest(stored_user.encode(), username.encode())
        return password_matches and username_matches
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


@dataclass(frozen=True)
class Session:
    username: str
    csrf_token: str
    expires_at: float


class SessionStore:
    """Opaque, process-local sessions; restarting the service invalidates every session."""

    def __init__(self, ttl_seconds: int = 1800) -> None:
        self.ttl_seconds = ttl_seconds
        self._sessions: dict[str, Session] = {}
        self._lock = threading.RLock()

    @staticmethod
    def _key(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def create(self, username: str) -> tuple[str, Session]:
        token = secrets.token_urlsafe(32)
        session = Session(username, secrets.token_urlsafe(32), time.time() + self.ttl_seconds)
        with self._lock:
            now = time.time()
            expired = [key for key, value in self._sessions.items() if value.expires_at <= now]
            for key in expired:
                del self._sessions[key]
            if len(self._sessions) >= 128:
                oldest = min(self._sessions, key=lambda key: self._sessions[key].expires_at)
                del self._sessions[oldest]
            self._sessions[self._key(token)] = session
        return token, session

    def get(self, token: str | None) -> Session | None:
        if not token:
            return None
        key = self._key(token)
        with self._lock:
            session = self._sessions.get(key)
            if session and session.expires_at <= time.time():
                del self._sessions[key]
                return None
            return session

    def revoke(self, token: str | None) -> None:
        if token:
            with self._lock:
                self._sessions.pop(self._key(token), None)
