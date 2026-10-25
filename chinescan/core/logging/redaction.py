"""Common redaction for credentials embedded in text or mappings."""

import re
from collections.abc import Mapping
from typing import Any

_SECRET = re.compile(r"(?i)(authorization|api[_-]?key|token|password|secret)(\s*[:=]\s*)([^\s,;]+)")


def redact(value: Any) -> Any:
    if isinstance(value, Mapping):
        secret_key = re.compile(r"(?i)(token|secret|password|api[_-]?key)")
        return {
            key: "[REDACTED]" if secret_key.search(str(key)) else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact(item) for item in value)
    if isinstance(value, str):
        return _SECRET.sub(r"\1\2[REDACTED]", value)
    return value


class RedactionFilter:
    def filter(self, record: Any) -> bool:
        record.msg = redact(record.getMessage())
        record.args = ()
        return True
