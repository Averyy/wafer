"""Per-domain rate limiting with configurable min-interval + jitter."""

import logging
import random
import time

logger = logging.getLogger("wafer")


class RateLimiter:
    """Enforces minimum intervals between requests to the same domain.

    Tracks the last request timestamp per domain and sleeps if a new
    request would arrive too soon.
    """

    def __init__(
        self,
        min_interval: float = 1.0,
        jitter: float = 0.5,
    ):
        self.min_interval = min_interval
        self.jitter = jitter
        self._last_request: dict[str, float] = {}

    def _delay_for(self, domain: str) -> float:
        """Calculate how long to wait before the next request to domain."""
        last = self._last_request.get(domain)
        if last is None:
            return 0.0
        elapsed = time.monotonic() - last
        target = self.min_interval + random.uniform(0, self.jitter)
        remaining = target - elapsed
        return max(0.0, remaining)

    def record(self, domain: str) -> None:
        """Record that a request was sent to this domain."""
        self._last_request[domain] = time.monotonic()

    def wait_sync(self, domain: str) -> float:
        """Block until it's safe to send a request. Returns delay applied."""
        delay = self._delay_for(domain)
        if delay > 0:
            logger.debug(
                "Rate limiter: waiting %.2fs for %s", delay, domain
            )
            time.sleep(delay)
        return delay

    async def wait_async(self, domain: str) -> float:
        """Async wait until it's safe to send a request. Returns delay applied."""
        import asyncio

        delay = self._delay_for(domain)
        if delay > 0:
            logger.debug(
                "Rate limiter: waiting %.2fs for %s", delay, domain
            )
            await asyncio.sleep(delay)
        return delay
