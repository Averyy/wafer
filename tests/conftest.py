"""Shared mock objects and session factories for wafer tests."""

import asyncio
import json

from wafer._base import (
    DEFAULT_CONNECT_TIMEOUT,
    DEFAULT_EMULATION,
    DEFAULT_HEADERS,
    DEFAULT_TIMEOUT,
)
from wafer._fingerprint import FingerprintManager

# ---------------------------------------------------------------------------
# Mock rnet types
# ---------------------------------------------------------------------------


class MockStatus:
    def __init__(self, code: int):
        self._code = code

    def as_int(self) -> int:
        return self._code

    def is_success(self) -> bool:
        return 200 <= self._code < 300


class MockHeaderMap:
    """Mock rnet HeaderMap with bytes keys and bytes values.

    Mirrors rnet's real HeaderMap behavior:
    - keys() returns unique bytes keys
    - get()/[] returns first value only
    - get_all() returns list of all values for a key
    """

    def __init__(self, data: dict[str, str] | None = None):
        self._raw: dict[bytes, list[bytes]] = {}
        for k, v in (data or {}).items():
            bk = k.lower().encode("ascii")
            if bk not in self._raw:
                self._raw[bk] = []
            self._raw[bk].append(v.encode("utf-8"))

    def keys(self):
        return list(self._raw.keys())

    def __getitem__(self, key):
        if isinstance(key, str):
            key = key.lower().encode("ascii")
        return self._raw[key][0]

    def get(self, key):
        try:
            return self[key]
        except KeyError:
            return None

    def get_all(self, key):
        if isinstance(key, str):
            key = key.lower().encode("ascii")
        return list(self._raw.get(key, []))


class MockResponse:
    def __init__(
        self,
        status_code: int,
        headers: dict[str, str] | None = None,
        body: str = "",
    ):
        self.status = MockStatus(status_code)
        self.headers = MockHeaderMap(headers)
        self._body = body

    def text(self):
        return self._body

    def bytes(self):
        return self._body.encode("utf-8")

    def json(self):
        return json.loads(self._body)


class AsyncMockResponse:
    """Mock response with async text() for AsyncSession tests."""

    def __init__(
        self,
        status_code: int,
        headers: dict[str, str] | None = None,
        body: str = "",
    ):
        self.status = MockStatus(status_code)
        self.headers = MockHeaderMap(headers)
        self._body = body

    async def text(self):
        return self._body

    async def bytes(self):
        return self._body.encode("utf-8")

    def json(self):
        return json.loads(self._body)


class MockJar:
    """Mock cookie jar that records add() calls."""

    def __init__(self):
        self.added = []

    def add(self, cookie_str, url):
        self.added.append((cookie_str, url))


class MockClient:
    """Mock rnet client that returns responses from a sequence.

    Unified superset: tracks request_count, last_kwargs, request_log,
    and optionally has a cookie_jar.
    """

    def __init__(
        self,
        responses: list[MockResponse | Exception],
        cookie_jar: MockJar | None = None,
    ):
        self._responses = responses
        self._index = 0
        self.request_count = 0
        self.last_kwargs: dict = {}
        self.request_log: list[tuple] = []
        self.cookie_jar = cookie_jar or MockJar()

    def request(self, method, url, **kwargs):
        self.last_kwargs = kwargs
        resp = self._responses[
            min(self._index, len(self._responses) - 1)
        ]
        self._index += 1
        self.request_count += 1
        self.request_log.append((method, url, kwargs))
        if isinstance(resp, Exception):
            raise resp
        return resp

    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self.request("POST", url, **kwargs)


class AsyncMockClient:
    """Async mock rnet client."""

    def __init__(
        self,
        responses: list[AsyncMockResponse | Exception],
        cookie_jar: MockJar | None = None,
    ):
        self._responses = responses
        self._index = 0
        self.request_count = 0
        self.last_kwargs: dict = {}
        self.request_log: list[tuple] = []
        self.cookie_jar = cookie_jar or MockJar()

    async def request(self, method, url, **kwargs):
        self.last_kwargs = kwargs
        resp = self._responses[
            min(self._index, len(self._responses) - 1)
        ]
        self._index += 1
        self.request_count += 1
        self.request_log.append((method, url, kwargs))
        if isinstance(resp, Exception):
            raise resp
        return resp

    async def get(self, url, **kwargs):
        return await self.request("GET", url, **kwargs)

    async def post(self, url, **kwargs):
        return await self.request("POST", url, **kwargs)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def to_async_responses(responses):
    """Convert MockResponse/Exception list to AsyncMockResponse list."""
    result = []
    for r in responses:
        if isinstance(r, Exception):
            result.append(r)
        else:
            # Reconstruct flat headers dict from MockHeaderMap
            headers = {}
            for bk, vals in r.headers._raw.items():
                headers[bk.decode()] = vals[0].decode()
            result.append(
                AsyncMockResponse(
                    r.status.as_int(), headers, r._body,
                )
            )
    return result


# ---------------------------------------------------------------------------
# Session factories
# ---------------------------------------------------------------------------


def make_sync_session(responses, **session_kwargs):
    """Create a SyncSession with a mocked client.

    All BaseSession attributes are defaulted. Override via session_kwargs:
    - max_retries, max_rotations, max_failures
    - follow_redirects, max_redirects
    - embed_origin, embed_referers
    - browser_solver
    - cookie_cache, rate_limiter
    """
    from wafer._sync import SyncSession

    session = SyncSession.__new__(SyncSession)

    session.headers = dict(DEFAULT_HEADERS)
    session.connect_timeout = DEFAULT_CONNECT_TIMEOUT
    session.timeout = DEFAULT_TIMEOUT
    session.max_retries = session_kwargs.get("max_retries", 3)
    session.max_rotations = session_kwargs.get("max_rotations", 10)

    session.max_failures = session_kwargs.get(
        "max_failures", 3
    )
    session._fingerprint = FingerprintManager(DEFAULT_EMULATION)
    session._cookie_cache = session_kwargs.get("cookie_cache", None)
    session._rate_limiter = session_kwargs.get("rate_limiter", None)
    session._domain_failures = {}
    session._last_url = {}
    embed_origin = session_kwargs.get("embed_origin", None)
    embed = session_kwargs.get("embed", None)
    if embed_origin and embed is None:
        embed = "xhr"
    session._embed = embed
    session._embed_origin = embed_origin
    session._embed_referers = session_kwargs.get(
        "embed_referers", []
    )
    session.follow_redirects = session_kwargs.get(
        "follow_redirects", True
    )
    session.max_redirects = session_kwargs.get("max_redirects", 10)
    session._browser_solver = session_kwargs.get(
        "browser_solver", None
    )
    session._proxy = None
    session._rotate_every = session_kwargs.get("rotate_every", None)
    session._request_count = 0
    session._profile = session_kwargs.get("profile", None)
    session._om_identity = None
    session._safari_identity = None
    session._client_headers = session._compute_client_headers()

    use_cookie_jar = session_kwargs.get("use_cookie_jar", False)
    jar = MockJar() if use_cookie_jar else None
    mock = MockClient(responses, cookie_jar=jar)
    session._client = mock
    session._rebuild_client = lambda: None
    session._retire_session = lambda domain: None
    return session, mock


def make_async_session(responses, **session_kwargs):
    """Create an AsyncSession with a mocked client."""
    from wafer._async import AsyncSession

    session = AsyncSession.__new__(AsyncSession)

    session.headers = dict(DEFAULT_HEADERS)
    session.connect_timeout = DEFAULT_CONNECT_TIMEOUT
    session.timeout = DEFAULT_TIMEOUT
    session.max_retries = session_kwargs.get("max_retries", 3)
    session.max_rotations = session_kwargs.get("max_rotations", 10)

    session.max_failures = session_kwargs.get(
        "max_failures", 3
    )
    session._fingerprint = FingerprintManager(DEFAULT_EMULATION)
    session._cookie_cache = session_kwargs.get("cookie_cache", None)
    session._rate_limiter = session_kwargs.get("rate_limiter", None)
    session._domain_failures = {}
    session._last_url = {}
    embed_origin = session_kwargs.get("embed_origin", None)
    embed = session_kwargs.get("embed", None)
    if embed_origin and embed is None:
        embed = "xhr"
    session._embed = embed
    session._embed_origin = embed_origin
    session._embed_referers = session_kwargs.get(
        "embed_referers", []
    )
    session.follow_redirects = session_kwargs.get(
        "follow_redirects", True
    )
    session.max_redirects = session_kwargs.get("max_redirects", 10)
    session._browser_solver = session_kwargs.get(
        "browser_solver", None
    )
    session._proxy = None
    session._rotate_every = session_kwargs.get("rotate_every", None)
    session._request_count = 0
    session._rotate_lock = asyncio.Lock()
    session._profile = session_kwargs.get("profile", None)
    session._om_identity = None
    session._safari_identity = None
    session._client_headers = session._compute_client_headers()

    async_responses = to_async_responses(responses)
    use_cookie_jar = session_kwargs.get("use_cookie_jar", False)
    jar = MockJar() if use_cookie_jar else None
    mock = AsyncMockClient(async_responses, cookie_jar=jar)
    session._client = mock
    session._rebuild_client = lambda: None

    async def _noop_retire(domain):
        pass

    session._retire_session = _noop_retire
    return session, mock
