"""WaferResponse -- user-friendly response wrapper."""

import codecs
import json
import re
from typing import Any, NamedTuple


class HistoryEntry(NamedTuple):
    """One followed redirect hop: the 3xx status and the URL that returned it.

    Compares equal to a plain ``(status_code, url)`` tuple.
    """

    status_code: int
    url: str


# Matches the charset declaration inside an HTML <meta> tag, covering both
# <meta charset="..."> and <meta http-equiv="content-type"
# content="text/html; charset=...">. Applied to the first 1KB of the body.
_META_CHARSET_RE = re.compile(
    rb"<meta[^>]{0,512}?charset\s*=\s*[\"']?([A-Za-z0-9][A-Za-z0-9._:\-]*)",
    re.IGNORECASE,
)


def _charset_from_content_type(content_type: str) -> str | None:
    """Extract the charset= parameter value from a Content-Type header."""
    for part in content_type.split(";")[1:]:
        key, _, value = part.partition("=")
        if key.strip().lower() == "charset":
            return value.strip().strip("'\"") or None
    return None


def _validate_charset(name: str | None) -> str | None:
    """Return ``name`` if it's a known Python codec, else None (never raises)."""
    if not name:
        return None
    try:
        codecs.lookup(name)
    except (LookupError, ValueError):
        return None
    return name


def resolve_charset(headers: dict[str, str], content: bytes) -> str:
    """Resolve a body's charset: header param, HTML meta tag, UTF-8.

    Resolution order:

    1. the ``charset=`` parameter of the Content-Type header
    2. a ``<meta charset=...>`` / ``<meta http-equiv="content-type">``
       tag in the first 1KB of the body -- only for HTML content types,
       or, when the Content-Type is missing entirely, for bodies that
       actually look like markup (first non-whitespace byte is ``<``).
       The markup check prevents codec confusion when a JSON/binary
       response with no Content-Type happens to contain a meta-like
       string.
    3. UTF-8

    Unknown/invalid charset names are skipped. Never raises.
    """
    content_type = headers.get("content-type", "")
    charset = _validate_charset(_charset_from_content_type(content_type))
    if charset:
        return charset
    mime = content_type.split(";")[0].strip().lower()
    head = content[:1024]
    # Ignore a leading UTF-8 BOM when checking whether the body is markup.
    stripped = head.lstrip()
    if stripped.startswith(b"\xef\xbb\xbf"):
        stripped = stripped[3:].lstrip()
    if "html" in mime or (not mime and stripped[:1] == b"<"):
        match = _META_CHARSET_RE.search(head)
        if match:
            charset = _validate_charset(
                match.group(1).decode("ascii", errors="replace")
            )
            if charset:
                return charset
    return "utf-8"


# Everything that contributes markup but no reading matter, stripped before
# measuring how much text a body actually carries.
_NON_TEXT_ELEMENT_RE = re.compile(
    r"(?is)<(script|style|noscript|template|svg)[^>]*>.*?</\1>"
)
_TAG_RE = re.compile(r"(?s)<[^>]+>")
# Below this many characters of visible text, an HTML body that ships script
# is a shell: the content is written by the client, not by the server.
_SHELL_TEXT_THRESHOLD = 1000


class WaferResponse:
    """Friendly response object wrapping raw wreq responses.

    Provides a requests/httpx-like API:
    - ``status_code``: int
    - ``content``: bytes (body after transport decompression, always available)
    - ``text``: str (decoded from content, lazy, charset-aware)
    - ``headers``: dict[str, str] (lowercase keys)
    - ``url``: final URL after redirects
    - ``history``: list[HistoryEntry] of followed redirect hops
    - ``cookies``: dict[str, str] of cookies set by this response
    - ``ok``: True if 200 <= status_code < 300
    - ``needs_render``: True if the body looks like a client-rendered shell
    - ``json()``: parsed JSON
    - ``raise_for_status()``: raises WaferHTTPError if not ok
    """

    __slots__ = (
        "status_code",
        "_content",
        "_text",
        "_cookies",
        "_needs_render",
        "_raw_set_cookie",
        "headers",
        "url",
        "history",
        "challenge_type",
        "was_retried",
        "retries",
        "rotations",
        "inline_solves",
        "elapsed",
        "emulation",
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
        history: list | None = None,
        challenge_type: str | None = None,
        was_retried: bool = False,
        retries: int = 0,
        rotations: int = 0,
        inline_solves: int = 0,
        elapsed: float = 0.0,
        emulation: str | None = None,
        raw=None,
        raw_set_cookie: list[str] | None = None,
    ):
        self.status_code = status_code
        # Derive content from text if not explicitly provided
        if not content and text is not None:
            content = text.encode("utf-8")
        self._content = content
        self._text = text
        self._cookies: dict[str, str] | None = None
        self._needs_render: bool | None = None
        # Individual Set-Cookie header values, preserved by transports
        # that decode headers into a flat dict (native-TLS, Opera Mini, browser)
        # where multiple Set-Cookie values would otherwise be joined.
        self._raw_set_cookie: list[str] | None = (
            list(raw_set_cookie) if raw_set_cookie is not None else None
        )
        self.headers = headers
        self.url = url
        self.history: list[HistoryEntry] = (
            list(history) if history is not None else []
        )
        self.challenge_type = challenge_type
        self.was_retried = was_retried
        self.retries = retries
        self.rotations = rotations
        self.inline_solves = inline_solves
        self.elapsed = elapsed
        # repr() of the Emulation (or profile name) that served the request,
        # e.g. "Profile.Chrome149". Populated by the session at construction;
        # lets callers diagnose which fingerprint served a 403/regression.
        self.emulation = emulation
        self._raw = raw

    @property
    def content(self) -> bytes:
        """Response body bytes after transport decompression."""
        return self._content

    @property
    def text(self) -> str:
        """Response body decoded as text (cached after first access).

        If the body was already decoded (text responses), returns the
        cached string. Otherwise decodes content using the charset
        resolved in this order:

        1. the ``charset=`` parameter of the Content-Type header
        2. for HTML bodies, a ``<meta charset=...>`` /
           ``<meta http-equiv="content-type" ...>`` tag in the first
           1KB of the body
        3. UTF-8

        Unknown/invalid charset names fall back to UTF-8. Decoding uses
        ``errors="replace"``, so this never raises.
        """
        if self._text is None:
            self._text = self._content.decode(
                self._charset(), errors="replace"
            )
        return self._text

    def _charset(self) -> str:
        """Resolve the body charset: header param, HTML meta tag, UTF-8."""
        return resolve_charset(self.headers, self._content)

    @property
    def cookies(self) -> dict[str, str]:
        """Cookies set by THIS response, parsed from its Set-Cookie headers.

        Name -> value only; attributes (Path, Domain, Expires, ...) are
        dropped. This is per-response, not the session's accumulated
        cookie state -- use ``session.get_cookie(name, url)`` for that.
        """
        if self._cookies is None:
            cookies: dict[str, str] = {}
            for raw in self.get_all("set-cookie"):
                pair = raw.split(";", 1)[0]
                name, sep, value = pair.partition("=")
                name = name.strip()
                if sep and name:
                    cookies[name] = value.strip()
            self._cookies = cookies
        return self._cookies

    @property
    def needs_render(self) -> bool:
        """Whether this body looks like a shell whose content is client-written.

        A hint, not a verdict: True when an HTML body ships script but almost
        no visible text, which is what a single-page app returns before its
        JavaScript runs. Answer it with ``session.render(url)``, which loads
        the page in a browser and returns the document after rendering
        settles. False for every non-HTML body.
        """
        if self._needs_render is None:
            self._needs_render = self._looks_like_shell()
        return self._needs_render

    def _looks_like_shell(self) -> bool:
        """Measure visible text against the markup that carries it."""
        mime = self.headers.get("content-type", "").split(";")[0].strip().lower()
        if mime and "html" not in mime and "xml" not in mime:
            return False
        body = self.text
        if not mime and not body.lstrip()[:1] == "<":
            return False
        if "<script" not in body.lower():
            return False
        text = _TAG_RE.sub(" ", _NON_TEXT_ELEMENT_RE.sub(" ", body))
        return len(" ".join(text.split())) < _SHELL_TEXT_THRESHOLD

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
            raise WaferHTTPError(self.status_code, self.url, response=self)

    def get_all(self, key: str) -> list[str]:
        """Return all values for a header key (e.g. individual Set-Cookie entries).

        Set-Cookie values are preserved individually on every transport:
        the wreq path reads them from the raw HeaderMap; the native-TLS
        and Opera Mini paths carry them in ``raw_set_cookie`` (their
        flat header dicts join multi-value headers with ``"; "``, which
        is ambiguous for Set-Cookie).
        """
        if (
            key.lower() == "set-cookie"
            and self._raw_set_cookie is not None
        ):
            return list(self._raw_set_cookie)
        if self._raw is None:
            val = self.headers.get(key, "")
            return [val] if val else []
        return [v.decode() if isinstance(v, bytes) else v
                for v in self._raw.headers.get_all(key)]

    def __repr__(self) -> str:
        return f"<WaferResponse [{self.status_code}]>"
