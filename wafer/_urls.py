"""URL checks shared by the session and the browser solver.

Core (no browser dependency): the session checks a caller's page URLs with the
same rule the solver applies before it navigates, so a page the browser would
refuse is refused, or passed over, where the session chooses it.
"""

from urllib.parse import urlparse


def valid_browser_url(value) -> bool:
    """Whether a value is structurally safe for a browser navigation."""

    if (
        not isinstance(value, str)
        or not value
        or len(value) > 8192
        or any(ord(char) <= 0x20 or ord(char) == 0x7F for char in value)
    ):
        return False
    try:
        parsed = urlparse(value)
        port = parsed.port
    except (TypeError, ValueError):
        return False
    return (
        parsed.scheme in {"http", "https"}
        and bool(parsed.hostname)
        and parsed.username is None
        and parsed.password is None
        and port != 0
    )
