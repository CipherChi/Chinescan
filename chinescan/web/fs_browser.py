"""HTTP-facing name for the core filesystem browsing service."""

from chinescan.core.fs_policy import FilesystemBrowserService

FilesystemBrowser = FilesystemBrowserService

__all__ = ["FilesystemBrowser", "FilesystemBrowserService"]
