"""Reddit's Android app API as a browser-free transport for Reddit JSON reads
and the app's GraphQL requests.

A logged-out web client asking Reddit for JSON gets the Shreddit
network-security gate, and since 2026-10-20 an established anonymous web
session does too. The official Android app reads listings from
``oauth.reddit.com`` with an anonymous token minted from its own public client
id, and threads, comments and profiles over GraphQL on ``gql-fed.reddit.com``
(REST thread reads are refused to every logged-out client). wafer presents
itself as one such install: a stable device id and phone, a real Play release,
the header sets the app's HTTP clients build, its signed analytics session,
and the TLS and HTTP/2 of the app's two network stacks: OkHttp on Android's
Conscrypt for the token and REST reads, Cronet 143 for GraphQL (both
ClientHellos matched to captures of the real app, 2026-10-31).

This module holds the parts that do not touch the network: the identity, the
URL mapping, token parsing and the persisted state. The sessions do the I/O.
See docs/ref-reddit.md.
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import random
import re
import string
import tempfile
import time
import uuid
from dataclasses import asdict, dataclass, field, fields, replace
from pathlib import Path
from urllib.parse import urljoin, urlparse, urlunparse

import wreq
from wreq import Emulation, Platform, Profile, http2
from wreq.tls import AlpnProtocol, ExtensionType, KeyShare, TlsOptions, TlsVersion

from wafer._bytes import as_bytes

logger = logging.getLogger("wafer")

# The official Android app's OAuth client id (public; shipped in every install).
REDDIT_APP_CLIENT_ID = "ohXpoqrZYub1kg"
REDDIT_APP_TOKEN_URL = "https://www.reddit.com/auth/v2/oauth/access-token/loid"
REDDIT_APP_API_HOST = "oauth.reddit.com"
# The app's GraphQL endpoint. The app reads threads, comments and profiles
# here (persisted queries POSTed as JSON); the route carries those POSTs with
# the app's token, and the caller sends the operation.
REDDIT_APP_GQL_HOST = "gql-fed.reddit.com"
# ``resp.emulation`` for a response the app transport served.
REDDIT_APP_IDENTITY = "reddit_app"

# The request identity below is the app's own (release 2026.44.0): its auth
# and REST clients are OkHttp, its GraphQL client goes over Cronet, which the
# app builds without brotli. docs/ref-reddit.md lists each request's headers.
_OKHTTP_ACCEPT_ENCODING = "gzip"
# OkHttp's MODERN_TLS suites in the order Android's Conscrypt offers them
# (captured from the app on Android 16, Conscrypt 360527520).
_OKHTTP_CIPHERS = (
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-RSA-CHACHA20-POLY1305",
    "ECDHE-RSA-AES128-SHA",
    "ECDHE-RSA-AES256-SHA",
    "AES128-GCM-SHA256",
    "AES256-GCM-SHA384",
    "AES128-SHA",
    "AES256-SHA",
)
_OKHTTP_SIGALGS = (
    "ecdsa_secp256r1_sha256",
    "rsa_pss_rsae_sha256",
    "rsa_pkcs1_sha256",
    "ecdsa_secp384r1_sha384",
    "rsa_pss_rsae_sha384",
    "rsa_pkcs1_sha384",
    "rsa_pss_rsae_sha512",
    "rsa_pkcs1_sha512",
    "rsa_pkcs1_sha1",
)
_OKHTTP_WINDOW = 16 * 1024 * 1024
_CRONET_ACCEPT_ENCODING = "gzip, deflate"
# The HTTP/2 priority header Cronet adds to a request at its default
# (MEDIUM) priority: urgency 1, incremental.
_CRONET_PRIORITY = "u=1, i"
_ACCEPT_LANGUAGE = "en-US"
_GQL_ACCEPT = "application/graphql-response+json, application/json"
_GQL_CONTENT_TYPE = "application/json; charset=utf-8"
# The app's GraphQL client makes up to this many attempts per operation.
_GQL_MAX_ATTEMPTS = 3
_TOKEN_SCOPES = ("*", "email", "pii", "adsread", "adsedit")
# The device class the app reports for a current flagship.
_DEVICE_TIER = "v2t1"
# (floor in Mbps, class) for X-Reddit-Http-QoS, highest first.
_QUALITY_CLASSES = (
    (20.0, "EXCELLENT"),
    (10.0, "GOOD"),
    (5.0, "STANDARD"),
    (2.0, "LIMITED"),
)
_AVC, _VP9, _HEVC, _AV1 = (
    "video/avc",
    "video/x-vnd.on2.vp9",
    "video/hevc",
    "video/av01",
)
# Phones an install runs on: Build.MODEL -> (Build.MANUFACTURER, display
# density, display width in pixels, hardware video decoders in the order the
# app lists them, the Android major the phone shipped with).
_PHONES = {
    "Pixel 7": ("Google", 2.625, 1080, (_AVC, _VP9, _HEVC, _AV1), 13),
    "Pixel 7a": ("Google", 2.625, 1080, (_AVC, _VP9, _HEVC, _AV1), 13),
    "Pixel 8": ("Google", 2.625, 1080, (_AVC, _VP9, _HEVC, _AV1), 14),
    "Pixel 8a": ("Google", 2.625, 1080, (_AVC, _VP9, _HEVC, _AV1), 14),
    "Pixel 9": ("Google", 2.625, 1080, (_AVC, _VP9, _HEVC, _AV1), 14),
}
# The app signs its analytics session into x-reddit-session with HMAC-SHA512
# under a key every install ships (public, like the client id).
_SESSION_SECRET = base64.b64decode("G0mP32i4zFWsTD3pY1Dj/ydl5yYF9aWyzPvnBflr/PU=")
_SESSION_KEY_TAG = "1ab1c15bb9f3183b5aea60ba9f1e12bde3fa4cc0960a80567455f7e106f123b1"
_SESSION_ID_CHARS = string.ascii_lowercase + string.ascii_uppercase + string.digits

# How the last app-route read ended (reddit_bootstrap_state()["app_last_outcome"]).
REDDIT_APP_OUTCOME_SERVED = "served"
REDDIT_APP_OUTCOME_TOKEN = "token"
REDDIT_APP_OUTCOME_GATE = "gate"
REDDIT_APP_OUTCOME_UNAUTHORIZED = "unauthorized"
REDDIT_APP_OUTCOME_TRANSPORT = "transport"
REDDIT_APP_OUTCOME_REDIRECT = "redirect"
REDDIT_APP_OUTCOME_RATELIMIT = "ratelimit"
# The edge refused a read no logged-out client is served (see
# reddit_app_only): returned or raised as a block, the route stays on.
REDDIT_APP_OUTCOME_REFUSED = "refused"
# After Reddit refuses the route (a token it will not grant, the edge turning
# the client away), reads use the web path for this long; after a transport
# error, for the shorter time.
REDDIT_APP_BACKOFF_SECONDS = 900.0
REDDIT_APP_TRANSPORT_BACKOFF_SECONDS = 60.0
# Time a read keeps for itself after a rate-limit wait: a wait that would
# leave less goes to the web path instead of timing out.
REDDIT_APP_READ_MARGIN = 2.0
# An analytics session idle this long is replaced, as the app starts a new
# one when it returns from the background.
REDDIT_APP_SESSION_IDLE_SECONDS = 30 * 60.0
# A token minted this recently is not reminted on a 401: the refusal is the
# API's answer for that endpoint (one that needs an account).
_TOKEN_RECENT_SECONDS = 120.0
# Longest rate-limit reset honored before a read (the API's window is 600 s).
_MAX_RATELIMIT_RESET = 900.0

# Real releases as (Play version, versionCode, minimum Android major), from
# the release listings in October 2026. Refresh when they age: an install that
# never updates is unusual, and Reddit can retire old builds.
_APP_RELEASES = (
    ("2026.42.0", 2642001, 12),
    ("2026.43.0", 2643041, 10),
    ("2026.44.0", 2644001, 10),
)
_ANDROID_MAJORS = (13, 14, 15, 16)

# A token is renewed this long before it expires (they last a day).
_TOKEN_REFRESH_MARGIN = 300.0
REDDIT_APP_TOKEN_MAX_BYTES = 16 * 1024
_TOKEN_RE = re.compile(r"[A-Za-z0-9._~+/=-]{16,4096}\Z")
_LOID_RE = re.compile(r"[A-Za-z0-9._~+/=:,-]{1,2048}\Z")
# A GraphQL operation name or persisted-query hash, as headers carry them.
_HEADER_VALUE_RE = re.compile(r"[A-Za-z0-9_]{1,128}\Z")
_MIN_EXPIRES_IN = 60
_MAX_EXPIRES_IN = 7 * 86_400

# Hosts whose JSON the app API serves. old.reddit.com is left alone: an
# explicit Old Reddit request is fetched as asked.
_WEB_JSON_HOSTS = frozenset({"reddit.com", "www.reddit.com", "new.reddit.com"})
_API_HOSTS = frozenset({"api.reddit.com", REDDIT_APP_API_HOST})

# The state file sits beside the cookie cache's per-domain *.json files; a
# different suffix keeps cookie hydration from ever reading it as a domain.
_STATE_FILE = "reddit-app.state"


# REST reads Reddit's edge refuses to every logged-out client since
# 2026-10-20, the app's anonymous token and an established anonymous web
# session alike: a thread and its comments, the comment streams, /api/info,
# /api/morechildren, a user's about page, r/all in any form (r/popular is
# served), and /by_id with more than one id (one id is served). The app reads
# threads, comments, profiles and post batches over GraphQL. Matched against
# the path with any ``.json`` suffix removed.
_ANON_REFUSED_PATH_RE = re.compile(
    r"/(?:comments/[^/]+(?:/.*)?"
    r"|r/[^/]+/comments(?:/.*)?"
    r"|r/all(?:/.*)?"
    r"|by_id/[^/]+(?:,|%2c)[^/]*"
    r"|api/(?:info|morechildren)"
    r"|(?:user|u)/[^/]+/about)/?",
    re.IGNORECASE,
)


def _plain_https(url: str):
    """``(host, parsed)`` for an https URL on the default port without
    credentials, else None."""
    try:
        parsed = urlparse(url)
        port = parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme != "https"
        or port not in (None, 443)
        or parsed.username is not None
        or parsed.password is not None
    ):
        return None
    return (parsed.hostname or "").rstrip(".").lower(), parsed


def reddit_app_gql_url(url: str) -> str | None:
    """``url`` on the app's GraphQL host, or None when it names another."""
    plain = _plain_https(url)
    if plain is None or plain[0] != REDDIT_APP_GQL_HOST:
        return None
    parsed = plain[1]
    return urlunparse(
        ("https", REDDIT_APP_GQL_HOST, parsed.path or "/", parsed.params,
         parsed.query, "")
    )


def reddit_anon_refused(url: str) -> bool:
    """Whether ``url`` is a Reddit JSON read the edge refuses to every
    logged-out client (see _ANON_REFUSED_PATH_RE)."""
    api_url = reddit_app_api_url(url)
    if api_url is None:
        return False
    path = urlparse(api_url).path
    if path.lower().endswith(".json"):
        path = path[: -len(".json")]
    return _ANON_REFUSED_PATH_RE.fullmatch(path) is not None


def reddit_json_read(url: str) -> bool:
    """Whether ``url`` reads Reddit JSON: a ``.json`` path on any Reddit web
    host (Old Reddit included) or any path on an API host."""
    plain = _plain_https(url)
    if plain is None:
        return False
    host, parsed = plain
    if host in _API_HOSTS:
        return True
    reddit = host == "reddit.com" or host.endswith(".reddit.com")
    return reddit and (parsed.path or "").lower().endswith(".json")


def reddit_gate_is_final(url: str) -> bool:
    """Whether Reddit's network-security gate on ``url`` is a final answer
    rather than a challenge: a read refused to every logged-out client, or a
    GraphQL request, which takes the app's token. No web bootstrap, retry or
    other identity changes either answer."""
    return reddit_anon_refused(url) or reddit_app_gql_url(url) is not None


def reddit_app_api_url(url: str) -> str | None:
    """The ``oauth.reddit.com`` URL serving ``url``, or None when the app API
    does not serve it (not a Reddit JSON read)."""
    plain = _plain_https(url)
    if plain is None:
        return None
    host, parsed = plain
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


def okhttp_tls_options() -> TlsOptions:
    """The ClientHello of OkHttp on Android: the platform's Conscrypt
    (BoringSSL) with OkHttp's MODERN_TLS cipher suites, no GREASE and
    BoringSSL's fixed extension order, asking for OCSP and SCTs. The app
    bundles no TLS provider of its own, so its auth and REST clients send
    this; captured from the app on Android 16 (JA4
    t13d1514h2_8daaf6152771_43ade6aba3df). Conscrypt is updated through
    Mainline, so it is the same on the Android versions the install picks."""
    return TlsOptions(
        cipher_list=":".join(_OKHTTP_CIPHERS),
        sigalgs_list=":".join(_OKHTTP_SIGALGS),
        curves_list="X25519:P-256:P-384",
        key_shares=[KeyShare.X25519],
        min_tls_version=TlsVersion.TLS_1_2,
        max_tls_version=TlsVersion.TLS_1_3,
        alpn_protocols=[AlpnProtocol.HTTP2, AlpnProtocol.HTTP1],
        enable_ocsp_stapling=True,
        enable_signed_cert_timestamps=True,
        grease_enabled=False,
        permute_extensions=False,
        preserve_tls13_cipher_list=True,
        extension_permutation=[
            ExtensionType.SERVER_NAME,
            ExtensionType.EXTENDED_MASTER_SECRET,
            ExtensionType.RENEGOTIATE,
            ExtensionType.SUPPORTED_GROUPS,
            ExtensionType.EC_POINT_FORMATS,
            ExtensionType.SESSION_TICKET,
            ExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
            ExtensionType.STATUS_REQUEST,
            ExtensionType.SIGNATURE_ALGORITHMS,
            ExtensionType.CERTIFICATE_TIMESTAMP,
            ExtensionType.KEY_SHARE,
            ExtensionType.PSK_KEY_EXCHANGE_MODES,
            ExtensionType.SUPPORTED_VERSIONS,
            ExtensionType.PADDING,
        ],
    )


def okhttp_http2_options() -> wreq.Http2Options:
    """OkHttp's HTTP/2: one SETTINGS entry (a 16 MiB stream window), a
    connection window raised to 16 MiB, pseudo-headers in m, p, a, s order."""
    return wreq.Http2Options(
        initial_window_size=_OKHTTP_WINDOW,
        initial_connection_window_size=_OKHTTP_WINDOW,
        settings_order=wreq.SettingsOrder(wreq.SettingId.INITIAL_WINDOW_SIZE),
        headers_pseudo_order=http2.PseudoOrder(
            http2.PseudoId.METHOD,
            http2.PseudoId.PATH,
            http2.PseudoId.AUTHORITY,
            http2.PseudoId.SCHEME,
        ),
    )


def cronet_emulation() -> Emulation:
    """The app's GraphQL client: its embedded Cronet (143.0.7445.0) over TCP
    sends Chrome 143's ClientHello (captured: the same ja4_r as this
    emulation, t13d1516h2_8daaf6152771_d8a2da3f94cd)."""
    return Emulation(
        profile=Profile.Chrome143, platform=Platform.Android, headers=False
    )


@dataclass(frozen=True)
class RedditAppDevice:
    """One app install on one phone: kept for the life of the cache."""

    device_id: str
    version: str
    build: int
    android: int
    # The bandwidth estimate a request reports varies around this, in Mbps.
    down_rate: str
    model: str = ""
    # Google advertising id ("" when the phone has none).
    ad_id: str = ""
    # Lowercase hex SHA-384 of the phone's Settings.Secure.ANDROID_ID.
    p_device_id: str = ""
    # The logged-out user id this install was given; sent on later mints.
    loid: str = field(default="", repr=False)

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
            **_new_phone(android, rng),
        )

    @property
    def user_agent(self) -> str:
        return (
            f"Reddit/Version {self.version}/Build {self.build}"
            f"/Android {self.android}"
        )

    @property
    def _phone(self) -> tuple:
        return _PHONES[self.model]

    def _network_headers(self) -> list[tuple[str, str]]:
        """What the app's shared client adds to every request: the network
        quality class and estimate (re-measured per request), the device
        class, compression and the hardware video decoders."""
        mbps = float(self.down_rate) * random.uniform(0.85, 1.15)
        quality = next(
            (name for floor, name in _QUALITY_CLASSES if mbps >= floor),
            "VERY_LIMITED",
        )
        return [
            ("X-Reddit-Http-QoS", quality),
            ("X-Reddit-Device-Tier", _DEVICE_TIER),
            ("x-reddit-compression", "1"),
            ("X-Reddit-QoS", f"down-rate-mbps={mbps:.3f}"),
            ("X-Reddit-Media-Codecs", "available-codecs=" + ", ".join(self._phone[3])),
        ]

    def _identity_headers(self) -> list[tuple[str, str]]:
        """What the app adds to an API request after Authorization."""
        density, width_px = self._phone[1], self._phone[2]
        return [
            ("Client-Vendor-ID", self.device_id),
            ("x-reddit-device-id", self.device_id),
            ("User-Agent", self.user_agent),
            ("X-Dev-Ad-Id", self.ad_id),
            ("Device-Name", f"{self._phone[0]};{self.model}"),
            # Java's String.valueOf(float) and (int) (widthPixels / density).
            ("x-reddit-dpr", repr(density)),
            ("x-reddit-width", str(int(width_px / density))),
        ]


def _new_phone(android: int, rng) -> dict[str, str]:
    model = rng.choice([m for m, p in _PHONES.items() if p[4] <= android])
    android_id = f"{rng.getrandbits(64):016x}"
    return {
        "model": model,
        "ad_id": str(uuid.uuid4()),
        "p_device_id": hashlib.sha384(android_id.encode()).hexdigest(),
    }


@dataclass(frozen=True)
class RedditAppAnalyticsSession:
    """The app's analytics session, which it signs into ``x-reddit-session``
    on every request: a new one per wafer session, as per app launch."""

    session_id: str = field(repr=False)
    created_ms: int

    @classmethod
    def new(cls) -> "RedditAppAnalyticsSession":
        rng = random.SystemRandom()
        return cls(
            session_id="".join(rng.choice(_SESSION_ID_CHARS) for _ in range(18)),
            created_ms=int(time.time() * 1000),
        )

    def header(self) -> str:
        payload = f"{self.session_id}.2.{self.created_ms}.{_SESSION_KEY_TAG}"
        mac = hmac.new(_SESSION_SECRET, payload.encode(), hashlib.sha512).digest()
        signature = base64.urlsafe_b64encode(mac).rstrip(b"=").decode()
        return f"{payload}-{signature}"


@dataclass(frozen=True)
class RedditAppToken:
    """An anonymous app token and the loid it was issued for."""

    access_token: str = field(repr=False)
    expires_at: float
    loid: str = field(default="", repr=False)
    minted_at: float = 0.0

    def fresh(self, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        return self.expires_at - _TOKEN_REFRESH_MARGIN > now

    def recent(self, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        return now - self.minted_at < _TOKEN_RECENT_SECONDS


def _optional(*pairs: tuple[str, str]) -> list[tuple[str, str]]:
    return [(name, value) for name, value in pairs if value]


def read_headers(
    device: RedditAppDevice,
    token: RedditAppToken,
    session: RedditAppAnalyticsSession,
) -> dict[str, str]:
    """A REST read, as the app's REST client (OkHttp) sends it."""
    return dict(
        device._network_headers()
        + [("Authorization", f"Bearer {token.access_token}")]
        + device._identity_headers()
        + _optional(
            ("x-reddit-loid", token.loid),
            ("x-reddit-session", session.header()),
            ("X-Reddit-P-Device-ID", device.p_device_id),
        )
        + [
            ("Accept-Language", _ACCEPT_LANGUAGE),
            ("Accept-Encoding", _OKHTTP_ACCEPT_ENCODING),
        ]
    )


def gql_headers(
    device: RedditAppDevice,
    token: RedditAppToken,
    session: RedditAppAnalyticsSession,
    payload: bytes,
    attempt: int = 0,
) -> dict[str, str]:
    """A GraphQL POST, as the app's Apollo client sends it over Cronet: the
    app's headers between the Content-Length Cronet sets first and the
    Accept-Encoding and priority it adds last. The operation headers repeat
    the payload's ``operationName`` and persisted query hash, and are left
    out when the payload does not carry them."""
    name, operation_id = _gql_operation(payload)
    return dict(
        [
            ("Content-Length", str(len(payload))),
            ("X-Reddit-Retry", f"attempt={attempt}, max={_GQL_MAX_ATTEMPTS}"),
        ]
        + _optional(
            ("X-APOLLO-OPERATION-NAME", name),
            ("X-APOLLO-OPERATION-ID", operation_id),
        )
        + [("accept", _GQL_ACCEPT)]
        + device._network_headers()
        + [
            ("Authorization", f"Bearer {token.access_token}"),
            ("Accept-Language", _ACCEPT_LANGUAGE),
        ]
        + device._identity_headers()
        + _optional(
            ("x-reddit-loid", token.loid),
            ("x-reddit-session", session.header()),
            ("X-Reddit-P-Device-ID", device.p_device_id),
        )
        + [
            ("Content-Type", _GQL_CONTENT_TYPE),
            ("Accept-Encoding", _CRONET_ACCEPT_ENCODING),
            ("priority", _CRONET_PRIORITY),
        ]
    )


def gql_payload(body_kwargs: dict) -> bytes:
    """The bytes a GraphQL POST sends: ``body=`` as given, ``json=``
    serialized compactly, as the app's JSON writer does."""
    if "json" in body_kwargs:
        return json.dumps(
            body_kwargs["json"], separators=(",", ":"), ensure_ascii=False
        ).encode()
    body = body_kwargs.get("body", b"")
    if isinstance(body, str):
        return body.encode()
    return as_bytes(body) if body is not None else b""


def _gql_operation(payload: bytes) -> tuple[str, str]:
    """``(operationName, persisted query hash)`` from a GraphQL payload, ""
    for either one it does not carry."""
    try:
        data = json.loads(payload)
    except (UnicodeDecodeError, ValueError):
        return "", ""
    if not isinstance(data, dict):
        return "", ""
    name = data.get("operationName")
    extensions = data.get("extensions")
    persisted = (
        extensions.get("persistedQuery") if isinstance(extensions, dict) else None
    )
    sha = persisted.get("sha256Hash") if isinstance(persisted, dict) else None
    return (
        name if isinstance(name, str) and _HEADER_VALUE_RE.match(name) else "",
        sha if isinstance(sha, str) and _HEADER_VALUE_RE.match(sha) else "",
    )


def _with_content_length(headers: dict[str, str], length: int) -> dict[str, str]:
    """``headers`` with Content-Length right after Content-Type, where
    OkHttp's BridgeInterceptor puts it."""
    out: dict[str, str] = {}
    for name, value in headers.items():
        out[name] = value
        if name == "Content-Type":
            out["Content-Length"] = str(length)
    return out


def token_request(
    device: RedditAppDevice, session: RedditAppAnalyticsSession
) -> tuple[dict[str, str], bytes]:
    """Headers and body of the anonymous token request, as the app's auth
    client (OkHttp) sends it."""
    basic = base64.b64encode(f"{REDDIT_APP_CLIENT_ID}:".encode()).decode()
    network = device._network_headers()
    headers = dict(
        [("Authorization", f"Basic {basic}")]
        + _optional(("x-reddit-loid", device.loid))
        + network[:2]
        + [("User-Agent", device.user_agent)]
        + network[2:]
        + [("Client-Vendor-ID", device.device_id)]
        + _optional(
            ("X-Reddit-P-Device-ID", device.p_device_id),
            ("x-reddit-session", session.header()),
        )
        + [
            ("Content-Type", "application/json; charset=UTF-8"),
            ("Accept-Encoding", _OKHTTP_ACCEPT_ENCODING),
        ]
    )
    body = json.dumps({"scopes": list(_TOKEN_SCOPES)}, separators=(",", ":"))
    return _with_content_length(headers, len(body)), body.encode()


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
    if loid and not _LOID_RE.match(loid):
        loid = ""
    now = time.time() if now is None else now
    return RedditAppToken(
        access_token=token,
        expires_at=now + expires_in,
        loid=loid,
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


def _current(device: RedditAppDevice) -> RedditAppDevice:
    """A stored install brought up to date: a release no longer in the table
    moves to a current build, as an updated app would, and an install from
    before phones were modelled (or on a phone no longer listed) gets one.
    The install id and loid are kept."""
    rng = random.SystemRandom()
    if device.version not in {r[0] for r in _APP_RELEASES}:
        fresh = RedditAppDevice.new()
        device = replace(
            device,
            version=fresh.version,
            build=fresh.build,
            android=max(device.android, fresh.android),
        )
    phone = _PHONES.get(device.model)
    if phone is None or phone[4] > device.android:
        device = replace(device, **_new_phone(device.android, rng))
    return device


def _known(cls, data: dict) -> dict:
    names = {f.name for f in fields(cls)}
    return {k: v for k, v in data.items() if k in names}


def load_state(
    cache_dir: Path | None,
) -> tuple[RedditAppDevice, RedditAppToken | None] | None:
    """The persisted install and token, or None if absent or unreadable."""
    if cache_dir is None:
        return None
    try:
        data = json.loads((cache_dir / _STATE_FILE).read_text())
        stored = RedditAppDevice(**_known(RedditAppDevice, data["device"]))
    except FileNotFoundError:
        return None
    except Exception:
        logger.debug("Reddit app state unreadable; starting a new install")
        return None
    # A damaged token costs only a mint; the install survives it.
    try:
        token = RedditAppToken(**_known(RedditAppToken, data["token"]))
        token.fresh()
    except Exception:
        token = None
    try:
        device = stored
        loid = getattr(token, "loid", "")
        if not device.loid and isinstance(loid, str) and _LOID_RE.match(loid):
            # Files from before the install kept its loid hold it on the token.
            device = replace(device, loid=loid)
        device = _current(device)
    except Exception:
        logger.debug("Reddit app state unreadable; starting a new install")
        return None
    if token is not None and not token.fresh():
        token = None
    if device != stored:
        # Keep the updated install, so every later load presents the same one.
        save_state(cache_dir, device, token)
    return device, token


def save_state(
    cache_dir: Path | None, device: RedditAppDevice, token: RedditAppToken | None
) -> None:
    """Persist the install and token owner-only, atomically."""
    if cache_dir is None:
        return
    data = {
        "device": asdict(device),
        "token": None if token is None else asdict(token),
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
