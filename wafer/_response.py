"""WaferResponse -- user-friendly response wrapper."""

import json
from typing import Any


class WaferResponse:
    """Friendly response object wrapping raw rnet responses.

    Provides a requests/httpx-like API:
    - ``status_code``: int
    - ``content``: bytes (raw response body, always available)
    - ``text``: str (decoded from content, lazy)
    - ``headers``: dict[str, str] (lowercase keys)
    - ``url``: final URL after redirects
    - ``ok``: True if 200 <= status_code < 300
    - ``json()``: parsed JSON
    - ``raise_for_status()``: raises WaferHTTPError if not ok
    """

    __slots__ = (
        "status_code",
        "_content",
        "_text",
        "headers",
        "url",
        "challenge_type",
        "was_retried",
        "elapsed",
        "_raw",
    )

    def __init__(
        self,
        *,
        status_code: int,
        headers: dict[str, str],
        url: str,
        content: bytes = b"",
        text: str | None = None,
        challenge_type: str | None = None,
        was_retried: bool = False,
        elapsed: float = 0.0,
        raw=None,
    ):
        self.status_code = status_code
        # Derive content from text if not explicitly provided
        if not content and text is not None:
            content = text.encode("utf-8")
        self._content = content
        self._text = text
        self.headers = headers
        self.url = url
        self.challenge_type = challenge_type
        self.was_retried = was_retried
        self.elapsed = elapsed
        self._raw = raw

    @property
    def content(self) -> bytes:
        """Raw response body as bytes."""
        return self._content

    @property
    def text(self) -> str:
        """Response body decoded as text.

        If the body was already decoded (text responses), returns the
        cached string. Otherwise decodes content as UTF-8 with
        replacement for invalid bytes.
        """
        if self._text is None:
            self._text = self._content.decode("utf-8", errors="replace")
        return self._text

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 300

    @property
    def retry_after(self) -> float | None:
        from wafer._retry import parse_retry_after

        return parse_retry_after(self.headers.get("retry-after", ""))

    def json(self, **kwargs) -> Any:
        return json.loads(self.text, **kwargs)

    def raise_for_status(self) -> None:
        from wafer._errors import WaferHTTPError

        if not self.ok:
            raise WaferHTTPError(self.status_code, self.url)

    def get_all(self, key: str) -> list[str]:
        """Return all values for a header key (e.g. individual Set-Cookie entries)."""
        if self._raw is None:
            val = self.headers.get(key, "")
            return [val] if val else []
        return [v.decode() if isinstance(v, bytes) else v
                for v in self._raw.headers.get_all(key)]

    def __repr__(self) -> str:
        return f"<WaferResponse [{self.status_code}]>"
