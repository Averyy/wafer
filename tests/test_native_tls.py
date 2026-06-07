"""Tests for the native-TLS (urllib/OpenSSL) Imperva fallback."""

import gzip
import zlib
from unittest.mock import AsyncMock, patch

import pytest

from wafer._base import BaseSession
from wafer._errors import ChallengeDetected
from wafer._fingerprint import host_user_agent
from wafer._native_tls import _decompress, sanitize_headers

from .conftest import MockResponse, make_async_session, make_sync_session

# ---------------------------------------------------------------------------
# Header sanitization
# ---------------------------------------------------------------------------


def test_sanitize_reduces_to_minimal_shape():
    out = sanitize_headers(
        {
            "User-Agent": "UA",
            "Origin": "https://www.realtor.ca",
            "Referer": "https://www.realtor.ca/",
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "sec-fetch-mode": "cors",
            "Sec-Fetch-Site": "same-site",
            "Sec-Fetch-Dest": "empty",
            "sec-ch-ua": '"Chrome"',
            "Sec-Ch-Ua-Platform": '"macOS"',
            "Upgrade-Insecure-Requests": "1",
            "Cache-Control": "max-age=0",
            "priority": "u=0, i",
        }
    )
    # Everything browser-typical and navigation-only is gone
    lowered = {k.lower() for k in out}
    assert not any(k.startswith("sec-fetch-") for k in lowered)
    assert not any(k.startswith("sec-ch-ua") for k in lowered)
    assert "upgrade-insecure-requests" not in lowered
    assert "cache-control" not in lowered
    assert "priority" not in lowered
    assert "accept-language" not in lowered
    assert "accept-encoding" not in lowered
    # Only the minimal API-client set survives
    assert out == {
        "User-Agent": "UA",
        "Origin": "https://www.realtor.ca",
        "Referer": "https://www.realtor.ca/",
        "Accept": "*/*",
    }


def test_host_user_agent_shape():
    ua = host_user_agent(147)
    assert ua.startswith("Mozilla/5.0")
    assert "Chrome/147.0.0.0" in ua
    assert ua.endswith("Safari/537.36")


# ---------------------------------------------------------------------------
# Body extraction
# ---------------------------------------------------------------------------


def test_extract_body_form():
    body, ct = BaseSession._extract_native_body({"form": {"a": "1", "b": "2"}})
    assert ct == "application/x-www-form-urlencoded"
    assert b"a=1" in body and b"b=2" in body


def test_extract_body_json():
    body, ct = BaseSession._extract_native_body({"json": {"a": 1}})
    assert ct == "application/json"
    assert body == b'{"a": 1}'


def test_extract_body_raw_str_and_bytes():
    assert BaseSession._extract_native_body({"body": "x"}) == (b"x", None)
    assert BaseSession._extract_native_body({"body": b"x"}) == (b"x", None)


def test_extract_body_none():
    assert BaseSession._extract_native_body({}) == (None, None)


# ---------------------------------------------------------------------------
# Decompression
# ---------------------------------------------------------------------------


def test_decompress_gzip_and_deflate():
    assert _decompress(gzip.compress(b"hello"), "gzip") == b"hello"
    assert _decompress(zlib.compress(b"hello"), "deflate") == b"hello"
    # raw deflate (no zlib header)
    co = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    raw = co.compress(b"hi") + co.flush()
    assert _decompress(raw, "deflate") == b"hi"


def test_decompress_identity_and_bad():
    assert _decompress(b"plain", "") == b"plain"
    assert _decompress(b"not-gzip", "gzip") == b"not-gzip"


# ---------------------------------------------------------------------------
# _native_prepare on a real session
# ---------------------------------------------------------------------------


def test_native_prepare_builds_clean_request():
    session, _ = make_sync_session([])
    headers, body = session._native_prepare(
        {
            "Origin": "https://www.realtor.ca",
            "Referer": "https://www.realtor.ca/",
            "Sec-Fetch-Mode": "cors",
        },
        {"form": {"Area": "Ottawa"}},
    )
    assert "Chrome/" in headers["User-Agent"]
    assert headers["Origin"] == "https://www.realtor.ca"
    assert headers["Content-Type"] == "application/x-www-form-urlencoded"
    assert not any(k.lower().startswith("sec-fetch") for k in headers)
    assert body == b"Area=Ottawa"


# ---------------------------------------------------------------------------
# Fake transport for integration tests
# ---------------------------------------------------------------------------


class FakeNativeTransport:
    """Stand-in for NativeTLSTransport that returns canned tuples."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    def request(self, method, url, headers, body=None, timeout=30.0):
        self.calls.append(
            {"method": method, "url": url, "headers": dict(headers), "body": body}
        )
        return self._responses.pop(0)


def _imperva_403():
    return MockResponse(
        403, {"x-cdn": "Imperva"}, "<html>Incapsula incident</html>"
    )


URL = "https://api2.realtor.ca/Location.svc/SubAreaSearch"
JSON_OK = (200, {"content-type": "application/json"}, b'{"ok": true}', URL)
NATIVE_CHALLENGE = (
    403, {"x-cdn": "Imperva", "content-type": "text/html"},
    b"<html>incapsula</html>", URL,
)
HDRS = {"Origin": "https://www.realtor.ca", "Referer": "https://www.realtor.ca/"}


# ---------------------------------------------------------------------------
# Async integration
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_async_imperva_bypassed_via_native_and_pinned():
    session, client = make_async_session([_imperva_403()], max_rotations=0)
    session._native_tls = FakeNativeTransport([JSON_OK])

    resp = await session.get(URL, headers=HDRS)

    assert resp.status_code == 200
    assert resp.challenge_type is None
    assert resp.json() == {"ok": True}
    # Host pinned to native for the rest of the session
    assert "api2.realtor.ca" in session._native_tls_domains
    # Native request carried sanitized headers + the Origin
    sent = session._native_tls.calls[0]["headers"]
    assert sent["Origin"] == "https://www.realtor.ca"
    assert not any(k.lower().startswith("sec-fetch") for k in sent)


@pytest.mark.asyncio
async def test_async_sticky_skips_wreq():
    # No wreq responses queued: if the wreq client were hit, it would error.
    session, client = make_async_session([], max_rotations=0)
    session._native_tls_domains.add("api2.realtor.ca")
    session._native_tls = FakeNativeTransport([JSON_OK])

    resp = await session.get(URL, headers=HDRS)

    assert resp.status_code == 200
    assert len(session._native_tls.calls) == 1


@pytest.mark.asyncio
async def test_async_native_challenge_does_not_pin():
    session, client = make_async_session([_imperva_403()], max_rotations=0)
    # Native also gets challenged (bypass not available on this site)
    session._native_tls = FakeNativeTransport(
        [(403, {"x-cdn": "Imperva", "content-type": "text/html"},
          b"<html>incapsula</html>", URL)]
    )

    resp = await session.get(URL, headers=HDRS)

    assert resp.status_code == 403
    assert resp.challenge_type == "imperva"
    assert "api2.realtor.ca" not in session._native_tls_domains


@pytest.mark.asyncio
async def test_async_post_form_goes_native():
    session, client = make_async_session([_imperva_403()], max_rotations=0)
    session._native_tls = FakeNativeTransport([JSON_OK])

    resp = await session.post(
        "https://api2.realtor.ca/Listing.svc/PropertySearch_Post",
        form={"GeoIds": "g30", "CurrentPage": "1"},
        headers=HDRS,
    )

    assert resp.status_code == 200
    call = session._native_tls.calls[0]
    assert call["method"] == "POST"
    assert call["body"] == b"GeoIds=g30&CurrentPage=1"
    assert call["headers"]["Content-Type"] == "application/x-www-form-urlencoded"


@pytest.mark.asyncio
async def test_async_sticky_rides_out_transient_challenge():
    # Pinned host hits a transient (rate-based) challenge, then recovers.
    session, client = make_async_session([], max_rotations=0)
    session._native_tls_domains.add("api2.realtor.ca")
    session._native_tls = FakeNativeTransport([NATIVE_CHALLENGE, JSON_OK])

    with patch("asyncio.sleep", new=AsyncMock()):
        resp = await session.get(URL, headers=HDRS)

    assert resp.status_code == 200
    # Retried native (challenge then success), never reverted to wreq.
    assert len(session._native_tls.calls) == 2
    assert "api2.realtor.ca" in session._native_tls_domains


@pytest.mark.asyncio
async def test_async_sticky_raises_after_native_retries_exhausted():
    # Pinned host stays challenged: retry native NATIVE_MAX_RETRIES times,
    # then raise (never falls back to a doomed wreq request).
    session, client = make_async_session([], max_rotations=2)
    session._native_tls_domains.add("api2.realtor.ca")
    session._native_tls = FakeNativeTransport([NATIVE_CHALLENGE] * 6)

    with patch("asyncio.sleep", new=AsyncMock()):
        with pytest.raises(ChallengeDetected) as exc:
            await session.get(URL, headers=HDRS)

    assert exc.value.challenge_type == "imperva"
    # initial attempt + NATIVE_MAX_RETRIES retries
    assert len(session._native_tls.calls) == 4


# ---------------------------------------------------------------------------
# Sync integration
# ---------------------------------------------------------------------------


def test_sync_imperva_bypassed_via_native_and_pinned():
    session, client = make_sync_session([_imperva_403()], max_rotations=0)
    session._native_tls = FakeNativeTransport([JSON_OK])

    resp = session.get(URL, headers=HDRS)

    assert resp.status_code == 200
    assert resp.challenge_type is None
    assert "api2.realtor.ca" in session._native_tls_domains


def test_sync_sticky_skips_wreq():
    session, client = make_sync_session([], max_rotations=0)
    session._native_tls_domains.add("api2.realtor.ca")
    session._native_tls = FakeNativeTransport([JSON_OK])

    resp = session.get(URL, headers=HDRS)

    assert resp.status_code == 200
    assert len(session._native_tls.calls) == 1


def test_sync_non_imperva_challenge_never_uses_native():
    # A Cloudflare challenge must not trigger the native fallback.
    session, client = make_sync_session(
        [MockResponse(403, {"cf-mitigated": "challenge"},
                      "<html>Just a moment...</html>")],
        max_rotations=0,
    )
    session._native_tls = FakeNativeTransport([JSON_OK])

    resp = session.get("https://example.com/x", headers=HDRS)

    assert resp.challenge_type == "cloudflare"
    assert len(session._native_tls.calls) == 0
    assert "example.com" not in session._native_tls_domains
