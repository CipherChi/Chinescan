"""Typed application exceptions and stable CLI exit statuses."""

from __future__ import annotations


class ChineScanError(Exception):
    """Base error for expected application failures."""

    exit_code = 1


class ConfigurationError(ChineScanError):
    """Invalid or unreadable configuration."""

    exit_code = 2


class StorageError(ChineScanError):
    """Persistence operation failed."""


EXIT_SUCCESS = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
