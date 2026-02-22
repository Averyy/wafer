"""Retry strategy: backoff, jitter, Retry-After parsing, separate counters."""

import datetime
import email.utils
import logging
import random

logger = logging.getLogger("wafer")


def parse_retry_after(value: str) -> float | None:
    """Parse Retry-After header (integer seconds or HTTP-date).

    Returns seconds to wait, or None if unparseable or empty.
    """
    if not value:
        return None

    # Try integer seconds
    try:
        return max(0.0, float(int(value)))
    except ValueError:
        pass

    # Try HTTP-date (RFC 7231 §7.1.1.1)
    try:
        parsed = email.utils.parsedate_to_datetime(value)
        delta = (
            parsed
            - datetime.datetime.now(datetime.timezone.utc)
        ).total_seconds()
        return max(0.0, delta)
    except (ValueError, TypeError):
        pass

    return None


def calculate_backoff(
    attempt: int,
    base: float = 1.0,
    max_delay: float = 30.0,
) -> float:
    """Exponential backoff with jitter.

    Returns delay in seconds: min(base * 2^attempt, max_delay) + jitter.
    Jitter is uniform random in [0, 0.5 * delay].
    """
    delay = min(base * (2**attempt), max_delay)
    jitter = random.uniform(0, delay * 0.5)
    return delay + jitter


class RetryState:
    """Tracks per-request retry counters.

    Two independent limits:
    - normal retries: for 5xx, timeouts, connection errors, empty bodies
    - rotation retries: for 403, 429, challenges (session identity issues)
    """

    def __init__(self, max_retries: int, max_rotations: int):
        self.max_retries = max_retries
        self.max_rotations = max_rotations
        self.normal_retries = 0
        self.rotation_retries = 0
        self.inline_solves = 0
        self.max_inline_solves = 3

    @property
    def can_retry(self) -> bool:
        return self.normal_retries < self.max_retries

    @property
    def can_rotate(self) -> bool:
        return self.rotation_retries < self.max_rotations

    def use_retry(self) -> None:
        self.normal_retries += 1

    def use_rotation(self) -> None:
        self.rotation_retries += 1
