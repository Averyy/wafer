"""wafer -- Anti-detection HTTP client for Python."""

import logging
from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("wafer-py")
except PackageNotFoundError:
    __version__ = "0.0.0"

from wafer._async import AsyncSession
from wafer._base import DEFAULT_HEADERS
from wafer._errors import (
    ChallengeDetected,
    ConnectionFailed,
    EmptyResponse,
    RateLimited,
    TooManyRedirects,
    WaferError,
    WaferHTTPError,
    WaferTimeout,
)
from wafer._profiles import Profile
from wafer._response import WaferResponse
from wafer._sync import SyncSession

__all__ = [
    "__version__",
    "SyncSession",
    "AsyncSession",
    "WaferResponse",
    "WaferError",
    "WaferHTTPError",
    "WaferTimeout",
    "ChallengeDetected",
    "RateLimited",
    "ConnectionFailed",
    "EmptyResponse",
    "TooManyRedirects",
    "Profile",
    "DEFAULT_HEADERS",
    "get",
    "post",
    "put",
    "delete",
    "head",
    "options",
    "patch",
]

# Silent by default; callers opt in via logging.getLogger("wafer").setLevel(...)
logging.getLogger("wafer").addHandler(logging.NullHandler())


def get(url: str, **kwargs):
    """Module-level convenience: one-shot sync GET."""
    with SyncSession() as s:
        return s.get(url, **kwargs)


def post(url: str, **kwargs):
    """Module-level convenience: one-shot sync POST."""
    with SyncSession() as s:
        return s.post(url, **kwargs)


def put(url: str, **kwargs):
    """Module-level convenience: one-shot sync PUT."""
    with SyncSession() as s:
        return s.put(url, **kwargs)


def delete(url: str, **kwargs):
    """Module-level convenience: one-shot sync DELETE."""
    with SyncSession() as s:
        return s.delete(url, **kwargs)


def head(url: str, **kwargs):
    """Module-level convenience: one-shot sync HEAD."""
    with SyncSession() as s:
        return s.head(url, **kwargs)


def options(url: str, **kwargs):
    """Module-level convenience: one-shot sync OPTIONS."""
    with SyncSession() as s:
        return s.options(url, **kwargs)


def patch(url: str, **kwargs):
    """Module-level convenience: one-shot sync PATCH."""
    with SyncSession() as s:
        return s.patch(url, **kwargs)
