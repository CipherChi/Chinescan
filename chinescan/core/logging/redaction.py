"""Single, defensive redaction implementation for logs and user-facing errors."""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from typing import Any

REDACTED = "[REDACTED]"
_SENSITIVE_KEY = re.compile(
    r"(?i)(?:password|passwd|pwd|hash|token|secret|api[_-]?key|apikey|authorization|"
    r"cookie|session|csrf|credential)"
)
_KEY_ASSIGNMENT = re.compile(
    r"(?i)(?P<prefix>[\"']?(?=[A-Za-z0-9_.-]*(?:password|passwd|pwd|hash|token|secret|"
    r"api[_-]?key|apikey|authorization|cookie|session|csrf|credential))"
    r"[A-Za-z_][A-Za-z0-9_.-]*[\"']?\s*[:=]\s*)"
    r"(?P<value>\"(?:\\.|[^\"\\\r\n])*\"|'(?:\\.|[^'\\\r\n])*'|<[^>]*>|[^\s,;}\]]+)"
)
_ARGON = re.compile(r"\$argon2(?:id|i|d)\$[^\s\"';}]+", re.IGNORECASE)
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*")
_UUID = re.compile(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
_TOKEN_RUN = re.compile(r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{32,}(?![A-Za-z0-9_-])")
_QUOTED_WINDOWS = re.compile(r"(?i)(?P<quote>[\"'])(?P<path>(?:[A-Z]:\\|\\\\)[^\"']+)\1")
_WINDOWS_PATH = re.compile(r"(?i)(?<![\w])(?:[A-Z]:\\|\\\\)[^\s\"'<>`,;)}\]]+")
_POSIX_PATH = re.compile(
    r"(?<![\w:/])/(?:Users|home|root|tmp|var/tmp|private/tmp|var/folders|etc|opt|mnt)/"
    r"[^\s\"'<>`,;)}\]]+"
)


def _redact_string(value: str) -> str:
    try:

        def assignment(match: re.Match[str]) -> str:
            prefix = match.group("prefix")
            raw = match.group("value")
            if raw[:1] in {"'", '"'} and raw[-1:] == raw[:1]:
                marker = f"{raw[0]}{REDACTED}{raw[0]}"
            elif raw.startswith("<") and raw.endswith(">"):
                marker = f"<{REDACTED}>"
            else:
                marker = REDACTED
            return prefix + marker

        value = _KEY_ASSIGNMENT.sub(assignment, value)
        value = _ARGON.sub(REDACTED, value)
        value = _BEARER.sub("Bearer " + REDACTED, value)
        for env_name in (
            "USERPROFILE",
            "HOME",
            "TEMP",
            "TMP",
            "APPDATA",
            "LOCALAPPDATA",
            "CHINESCAN_CONFIG_PATH",
            "CHINESCAN_DATABASE_PATH",
            "CHINESCAN_REPORTS_DIR",
        ):
            root = os.environ.get(env_name)
            if root:
                value = re.sub(re.escape(root), "[PATH]", value, flags=re.IGNORECASE)
        value = _QUOTED_WINDOWS.sub(
            lambda match: match.group("quote") + "[PATH]" + match.group("quote"), value
        )
        value = _WINDOWS_PATH.sub("[PATH]", value)
        value = _POSIX_PATH.sub("[PATH]", value)

        def token_replacement(match: re.Match[str]) -> str:
            candidate = match.group(0)
            if _UUID.fullmatch(candidate) or re.fullmatch(r"(?i)[a-f0-9]{32,}", candidate):
                return candidate
            classes = sum(
                bool(re.search(pattern, candidate))
                for pattern in (r"[a-z]", r"[A-Z]", r"[0-9]", r"[_-]")
            )
            return REDACTED if classes >= 2 else candidate

        value = _TOKEN_RUN.sub(token_replacement, value)
        return value
    except Exception:
        return REDACTED


def redact(value: Any) -> Any:
    """Redact sensitive fields and values recursively; safe for arbitrary inputs."""
    try:
        if isinstance(value, Mapping):
            output: dict[Any, Any] = {}
            for key, item in value.items():
                safe_key = _redact_string(key) if isinstance(key, str) else key
                output[safe_key] = REDACTED if _SENSITIVE_KEY.search(str(key)) else redact(item)
            return output
        if isinstance(value, list):
            return [redact(item) for item in value]
        if isinstance(value, tuple):
            return tuple(redact(item) for item in value)
        if isinstance(value, set):
            return {redact(item) for item in value}
        if isinstance(value, str):
            return _redact_string(value)
        if isinstance(value, bytes):
            try:
                return _redact_string(value.decode("utf-8", errors="replace"))
            except Exception:
                return REDACTED
        return value
    except Exception:
        return REDACTED
