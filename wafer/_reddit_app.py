"""Reddit's Android app API as a browser-free transport for Reddit JSON reads.

A logged-out web client asking Reddit for JSON gets the Shreddit
network-security gate, and the web verification that clears it can escalate
to a reCAPTCHA. The official Android app reads the same listings from
``oauth.reddit.com`` with an anonymous token minted from its own public client
id, which is what every logged-out install does. wafer presents itself as one
such install: a stable device id, a real Play release, the app's headers, and
the TLS of the network stack the app ships (Chromium's, not stock OkHttp: an
OkHttp ClientHello is refused with the network-security page, while a Chromium
one is served; measured 2026-09-27).

This module holds the parts that do not touch the network: the identity, the
URL mapping, token parsing and the persisted state. The sessions do the I/O.
See docs/ref-reddit.md.
"""

import base64
import json
import logging
import os
import random
import re
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urljoin, urlparse, urlunparse

logger = logging.getLogger("wafer")

# The official Android app's OAuth client id (public; shipped in every install).
REDDIT_APP_CLIENT_ID = "ohXpoqrZYub1kg"
REDDIT_APP_TOKEN_URL = "https://www.reddit.com/auth/v2/oauth/access-token/loid"
REDDIT_APP_API_HOST = "oauth.reddit.com"
# ``resp.emulation`` for a response the app transport served.
REDDIT_APP_IDENTITY = "reddit_app"
# What Chromium's network stack advertises.
_ACCEPT_ENCODING = "gzip, deflate, br, zstd"

# How the last app-route read ended (reddit_bootstrap_state()["app_last_outcome"]).
REDDIT_APP_OUTCOME_SERVED = "served"
REDDIT_APP_OUTCOME_TOKEN = "token"
REDDIT_APP_OUTCOME_GATE = "gate"
REDDIT_APP_OUTCOME_UNAUTHORIZED = "unauthorized"
REDDIT_APP_OUTCOME_TRANSPORT = "transport"
REDDIT_APP_OUTCOME_REDIRECT = "redirect"
REDDIT_APP_OUTCOME_RATELIMIT = "ratelimit"
# After Reddit refuses the route (a token it will not grant, the edge turning
# the client away), reads use the web path for this long; after a transport
# error, for the shorter time.
REDDIT_APP_BACKOFF_SECONDS = 900.0
REDDIT_APP_TRANSPORT_BACKOFF_SECONDS = 60.0
# Time a read keeps for itself after a rate-limit wait: a wait that would
# leave less goes to the web path instead of timing out.
REDDIT_APP_READ_MARGIN = 2.0
# A token minted this recently is not reminted on a 401: the refusal is the
# API's answer for that endpoint (one that needs an account).
_TOKEN_RECENT_SECONDS = 120.0
# Longest rate-limit reset honored before a read (the API's window is 600 s).
_MAX_RATELIMIT_RESET = 900.0

# Real releases as (Play version, versionCode, minimum Android major), from
# the Play listing in September 2026. Refresh when they age: an install that
# never updates is unusual, and Reddit can retire old builds.
_APP_RELEASES = (
    ("2026.37.0", 2637051, 10),
    ("2026.38.0", 2638050, 10),
    ("2026.39.0", 2639031, 12),
)
_ANDROID_MAJORS = (13, 14, 15)

# A token is renewed this long before it expires (they last a day).
_TOKEN_REFRESH_MARGIN = 300.0
REDDIT_APP_TOKEN_MAX_BYTES = 16 * 1024
_TOKEN_RE = re.compile(r"[A-Za-z0-9._~+/=-]{16,4096}\Z")
_SESSION_VALUE_RE = re.compile(r"[A-Za-z0-9._~+/=:,-]{1,2048}\Z")
_MIN_EXPIRES_IN = 60
_MAX_EXPIRES_IN = 7 * 86_400

# Hosts whose JSON the app API serves. old.reddit.com is left alone: an
# explicit Old Reddit request is fetched as asked.
_WEB_JSON_HOSTS = frozenset({"reddit.com", "www.reddit.com", "new.reddit.com"})
_API_HOSTS = frozenset({"api.reddit.com", REDDIT_APP_API_HOST})

# The state file sits beside the cookie cache's per-domain *.json files; a
# different suffix keeps cookie hydration from ever reading it as a domain.
_STATE_FILE = "reddit-app.state"


def reddit_app_api_url(url: str) -> str | None:
    """The ``oauth.reddit.com`` URL serving ``url``, or None when the app API
    does not serve it (not a Reddit JSON read)."""
    try:
        parsed = urlparse(url)
        port = parsed.port
    except ValueError:
        return None
    host = (parsed.hostname or "").rstrip(".").lower()
    if (
        parsed.scheme != "https"
        or port not in (None, 443)
        or parsed.username is not None
        or parsed.password is not None
    ):
        return None
    path = parsed.path or "/"
    if host in _API_HOSTS:
        pass
    elif host in _WEB_JSON_HOSTS and path.endswith(".json"):
        pass
    else:
        return None
    return urlunparse(
        ("https", REDDIT_APP_API_HOST, path, parsed.params, parsed.query, "")
    )


def reddit_app_redirect(api_url: str, location: str) -> str | None:
    """The app-API URL a redirect from ``api_url`` leads to, or None when the
    target is not a JSON read the app serves."""
    return reddit_app_api_url(urljoin(api_url, location))


def web_url(requested: str, api_url: str) -> str:
    """``api_url`` as seen from the host the caller asked for, so a response
    carries the URL the web path would have reported."""
    req = urlparse(requested)
    api = urlparse(api_url)
    return urlunparse((req.scheme, req.netloc, api.path, api.params, api.query, ""))


def caller_location(requested: str, api_url: str, location: str) -> str:
    """A Location header as the caller should see it: a target on the app API
    host is reported on the host the caller asked for."""
    target = urljoin(api_url, location)
    try:
        host = (urlparse(target).hostname or "").lower()
    except ValueError:
        return location
    return web_url(requested, target) if host == REDDIT_APP_API_HOST else location


@dataclass(frozen=True)
class RedditAppDevice:
    """One app install: kept for the life of the cache, like a real phone."""

    device_id: str
    version: str
    build: int
    android: int
    down_rate: str

    @classmethod
    def new(cls) -> "RedditAppDevice":
        rng = random.SystemRandom()
        android = rng.choice(_ANDROID_MAJORS)
        version, build, _ = rng.choice(
            [r for r in _APP_RELEASES if r[2] <= android]
        )
        return cls(
            device_id=str(uuid.uuid4()),
            version=version,
            build=build,
            android=android,
            down_rate=f"{rng.uniform(8.0, 95.0):.3f}",
        )

    @property
    def user_agent(self) -> str:
        return (
            f"Reddit/Version {self.version}/Build {self.build}"
            f"/Android {self.android}"
        )

    def headers(self) -> dict[str, str]:
        return {
            "User-Agent": self.user_agent,
            "client-vendor-id": self.device_id,
            "x-reddit-device-id": self.device_id,
            "x-reddit-retry": "algo=no-retries",
            "x-reddit-compression": "1",
            "x-reddit-qos": f"down-rate-mbps={self.down_rate}",
            "x-reddit-media-codecs": "available-codecs=video/avc, video/hevc",
        }


@dataclass(frozen=True)
class RedditAppToken:
    """An anonymous app token and the loid session it belongs to."""

    access_token: str = field(repr=False)
    expires_at: float
    loid: str = field(default="", repr=False)
    session: str = field(default="", repr=False)
    minted_at: float = 0.0

    def fresh(self, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        return self.expires_at - _TOKEN_REFRESH_MARGIN > now

    def recent(self, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        return now - self.minted_at < _TOKEN_RECENT_SECONDS

    def headers(self) -> dict[str, str]:
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Accept-Encoding": _ACCEPT_ENCODING,
        }
        if self.loid:
            headers["x-reddit-loid"] = self.loid
        if self.session:
            headers["x-reddit-session"] = self.session
        return headers


def token_request(device: RedditAppDevice) -> tuple[dict[str, str], bytes]:
    """Headers and body of the anonymous token request."""
    basic = base64.b64encode(f"{REDDIT_APP_CLIENT_ID}:".encode()).decode()
    headers = dict(device.headers())
    headers["Authorization"] = f"Basic {basic}"
    headers["Content-Type"] = "application/json; charset=UTF-8"
    headers["Accept-Encoding"] = _ACCEPT_ENCODING
    body = json.dumps({"scopes": ["*", "email", "pii"]}).encode()
    return headers, body


def parse_token_response(
    status: int, headers: dict[str, str], body: bytes, now: float | None = None
) -> RedditAppToken | None:
    """The token from a token response, or None unless it is a well-formed
    grant (a gate page, an error or anything malformed is refused)."""
    if status != 200 or len(body) > REDDIT_APP_TOKEN_MAX_BYTES:
        return None
    try:
        data = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    token = data.get("access_token")
    expires_in = data.get("expires_in")
    if (
        not isinstance(token, str)
        or not _TOKEN_RE.match(token)
        or not isinstance(expires_in, int)
        or isinstance(expires_in, bool)
        or not _MIN_EXPIRES_IN <= expires_in <= _MAX_EXPIRES_IN
    ):
        return None
    lower = {k.lower(): v for k, v in headers.items()}
    loid = lower.get("x-reddit-loid", "")
    session = lower.get("x-reddit-session", "")
    if loid and not _SESSION_VALUE_RE.match(loid):
        loid = ""
    if session and not _SESSION_VALUE_RE.match(session):
        session = ""
    now = time.time() if now is None else now
    return RedditAppToken(
        access_token=token,
        expires_at=now + expires_in,
        loid=loid,
        session=session,
        minted_at=now,
    )


def is_gate_response(status: int, headers: dict[str, str], body: bytes) -> bool:
    """Whether an answer is Reddit's edge turning the app client away (an HTML
    or other non-JSON page) rather than the API answering, which it always
    does in JSON (a private subreddit's 403 included). Redirects and server
    errors are judged elsewhere."""
    stripped = body.strip()
    if 300 <= status < 400 or status >= 500 or not stripped:
        return False
    content_type = {k.lower(): v for k, v in headers.items()}.get("content-type", "")
    if "json" in content_type.lower():
        return False
    # Without a declared type, a JSON-shaped body is still the API answering.
    return bool(content_type) or stripped[:1] not in (b"{", b"[")


def mint_backoff(status: int | None) -> float:
    """How long the route stays off after a failed mint: briefly when nothing
    or a transient error answered, long when Reddit refused the grant."""
    if status is None or status == 429 or status >= 500:
        return REDDIT_APP_TRANSPORT_BACKOFF_SECONDS
    return REDDIT_APP_BACKOFF_SECONDS


def ratelimit_reset(headers: dict[str, str]) -> float | None:
    """Seconds until the API's rate-limit window resets when this response
    used the last request in it, else None."""
    lower = {k.lower(): v for k, v in headers.items()}
    try:
        remaining = float(lower["x-ratelimit-remaining"])
        reset = float(lower["x-ratelimit-reset"])
    except (KeyError, TypeError, ValueError):
        return None
    if remaining >= 1 or not 0 < reset <= _MAX_RATELIMIT_RESET:
        return None
    return reset


def load_state(
    cache_dir: Path | None,
) -> tuple[RedditAppDevice, RedditAppToken | None] | None:
    """The persisted install and token, or None if absent or unreadable."""
    if cache_dir is None:
        return None
    try:
        data = json.loads((cache_dir / _STATE_FILE).read_text())
        device = RedditAppDevice(**data["device"])
        if device.version not in {r[0] for r in _APP_RELEASES}:
            # A release no longer in the table: keep the install id, move to
            # a current build as an updated app would.
            fresh = RedditAppDevice.new()
            device = RedditAppDevice(
                device_id=device.device_id,
                version=fresh.version,
                build=fresh.build,
                android=max(device.android, fresh.android),
                down_rate=device.down_rate,
            )
    except FileNotFoundError:
        return None
    except Exception:
        logger.debug("Reddit app state unreadable; starting a new install")
        return None
    # A damaged token costs only a mint; the install survives it.
    try:
        token = RedditAppToken(**data["token"])
        if not token.fresh():
            token = None
    except Exception:
        token = None
    return device, token


def save_state(
    cache_dir: Path | None, device: RedditAppDevice, token: RedditAppToken | None
) -> None:
    """Persist the install and token owner-only, atomically."""
    if cache_dir is None:
        return
    data = {
        "device": {
            "device_id": device.device_id,
            "version": device.version,
            "build": device.build,
            "android": device.android,
            "down_rate": device.down_rate,
        },
        "token": None
        if token is None
        else {
            "access_token": token.access_token,
            "expires_at": token.expires_at,
            "loid": token.loid,
            "session": token.session,
            "minted_at": token.minted_at,
        },
    }
    try:
        cache_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd, tmp = tempfile.mkstemp(dir=cache_dir, prefix=".reddit-app.", suffix=".tmp")
        try:
            if hasattr(os, "fchmod"):
                os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w") as f:
                json.dump(data, f)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, cache_dir / _STATE_FILE)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    except Exception:
        logger.debug("Could not persist Reddit app state", exc_info=True)
