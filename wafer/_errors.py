"""Typed exceptions for wafer."""


class WaferError(Exception):
    """Base exception for all wafer errors."""


class ChallengeDetected(WaferError):
    """A WAF challenge was detected and could not be solved.

    ``response`` carries the final challenge ``WaferResponse`` (body,
    headers, status code) when one was in hand at raise time, else None.

    Caution: ``response`` may carry a full WAF challenge page with
    embedded tokens/sensor data -- do not log its body or headers
    unscrubbed.
    """

    def __init__(
        self,
        challenge_type: str,
        url: str,
        status_code: int,
        response=None,
    ):
        self.challenge_type = challenge_type
        self.url = url
        self.status_code = status_code
        self.response = response
        super().__init__(
            f"{challenge_type} challenge detected at {url} (HTTP {status_code})"
        )


class RateLimited(WaferError):
    """Request was rate-limited (HTTP 429).

    ``response`` carries the final 429 ``WaferResponse`` (body, headers,
    status code) when one was in hand at raise time, else None.

    Caution: ``response`` may carry a full WAF challenge page with
    embedded tokens/sensor data -- do not log its body or headers
    unscrubbed.
    """

    def __init__(
        self,
        url: str,
        retry_after: float | None = None,
        response=None,
    ):
        self.url = url
        self.retry_after = retry_after
        self.response = response
        msg = f"Rate limited at {url}"
        if retry_after is not None:
            msg += f" (retry after {retry_after}s)"
        super().__init__(msg)


class ConnectionFailed(WaferError):
    """Failed to establish a connection."""

    def __init__(self, url: str, reason: str):
        self.url = url
        self.reason = reason
        super().__init__(f"Connection failed to {url}: {reason}")


class EmptyResponse(WaferError):
    """Server returned an empty response body.

    ``response`` carries the final empty ``WaferResponse`` (headers,
    status code) when one was in hand at raise time, else None.

    Caution: ``response`` headers may include WAF cookies/tokens -- do
    not log it unscrubbed.
    """

    def __init__(self, url: str, status_code: int, response=None):
        self.url = url
        self.status_code = status_code
        self.response = response
        super().__init__(f"Empty response from {url} (HTTP {status_code})")


class TooManyRedirects(WaferError):
    """Exceeded the maximum number of redirects."""

    def __init__(self, url: str, max_redirects: int):
        self.url = url
        self.max_redirects = max_redirects
        super().__init__(
            f"Too many redirects ({max_redirects}) for {url}"
        )


class WaferTimeout(WaferError, TimeoutError):
    """Request exceeded its timeout deadline."""

    def __init__(self, url: str, timeout_secs: float):
        self.url = url
        self.timeout_secs = timeout_secs
        super().__init__(
            f"Request to {url} exceeded {timeout_secs:.1f}s timeout"
        )


class WaferHTTPError(WaferError):
    """HTTP error raised by raise_for_status()."""

    def __init__(self, status_code: int, url: str):
        self.status_code = status_code
        self.url = url
        super().__init__(
            f"HTTP {status_code} at {url}"
        )
