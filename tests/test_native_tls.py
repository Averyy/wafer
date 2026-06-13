"""Tests for the native-TLS (urllib/OpenSSL) Imperva fallback."""

import gzip
import zlib
from types import SimpleNamespace
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
        self.seeded = []

    def request(self, method, url, headers, body=None, timeout=30.0):
        self.calls.append(
            {"method": method, "url": url, "headers": dict(headers), "body": body}
        )
        return self._responses.pop(0)

    def add_cookies(self, cookies):
        self.seeded.extend(cookies)


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

# Real transports return a 5th element: the individual Set-Cookie values
# (the flat headers dict joins them with "; ", lossy for cookies).
MULTI_SET_COOKIE = [
    "reese84=tok123; Path=/; Secure; HttpOnly",
    "incap_ses_1226_9=abc; Path=/",
]
JSON_OK_MULTI_COOKIE = (
    200,
    {
        "content-type": "application/json",
        "set-cookie": "; ".join(MULTI_SET_COOKIE),
    },
    b'{"ok": true}',
    URL,
    MULTI_SET_COOKIE,
)


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
    # Pinned host stays challenged and NO browser_solver: retry native
    # NATIVE_MAX_RETRIES times, then raise (the token can't be minted).
    session, client = make_async_session([], max_rotations=2)
    session._native_tls_domains.add("api2.realtor.ca")
    session._native_tls = FakeNativeTransport([NATIVE_CHALLENGE] * 6)

    with patch("asyncio.sleep", new=AsyncMock()):
        with pytest.raises(ChallengeDetected) as exc:
            await session.get(URL, headers=HDRS)

    assert exc.value.challenge_type == "imperva"
    # initial attempt + NATIVE_MAX_RETRIES retries
    assert len(session._native_tls.calls) == 4


@pytest.mark.asyncio
async def test_async_sticky_exhausted_reaches_browser_solve():
    # Pinned host stays challenged (heavy reese84 state) AND a browser_solver
    # is set: un-pin, fall through to wreq, and -because the rotation budget is
    # force-exhausted- the very first wreq Imperva 403 goes straight to the
    # browser solve (no wasted Safari/Chrome rotations). The browser injects
    # the token and the retried wreq request succeeds.
    pytest.importorskip("wafer.browser")  # _try_browser_solve needs [browser]

    class _Solver:
        def __init__(self):
            self.solve_calls = []

        def solve(self, url, challenge_type=None, timeout=None,
                  embedder=None, replay=None):
            self.solve_calls.append((url, challenge_type))
            return SimpleNamespace(
                cookies=[{"name": "reese84", "value": "t",
                          "domain": ".realtor.ca", "path": "/", "expires": -1,
                          "secure": True, "httpOnly": True, "sameSite": "None"}],
                user_agent="Mozilla/5.0 Chrome/147.0.0.0",
                extras=None, response=None,
            )

        def close(self):
            pass

    solver = _Solver()
    # wreq sees an Imperva 403 after the fall-through, then 200 post-solve.
    session, client = make_async_session(
        [_imperva_403(), MockResponse(200, body='{"ok": 1}')],
        max_rotations=2, browser_solver=solver, use_cookie_jar=True,
    )
    session._native_tls_domains.add("api2.realtor.ca")
    session._native_tls = FakeNativeTransport([NATIVE_CHALLENGE] * 6)

    with patch("asyncio.sleep", new=AsyncMock()):
        resp = await session.get(URL, headers=HDRS)

    assert resp.status_code == 200
    assert "api2.realtor.ca" not in session._native_tls_domains  # un-pinned
    assert len(session._native_tls.calls) == 4  # native exhausted first
    assert len(solver.solve_calls) == 1  # browser reached, no wasted rotations
    assert solver.solve_calls[0][1] == "imperva"


@pytest.mark.asyncio
async def test_async_trigger_native_fail_reaches_browser_not_rotation():
    # Unpinned host, native probe fails (heavy/non-free-pass), browser set:
    # rotation can't help Imperva (BoringSSL), so the browser solve must be
    # reached directly. With [403, 200] queued, a *rotation* would resolve on
    # the second wreq (solve_calls==0); the rotation-skip routes to the browser
    # instead (solve_calls==1).
    pytest.importorskip("wafer.browser")

    class _Solver:
        def __init__(self):
            self.solve_calls = []

        def solve(self, url, challenge_type=None, timeout=None,
                  embedder=None, replay=None):
            self.solve_calls.append((url, challenge_type))
            return SimpleNamespace(
                cookies=[{"name": "reese84", "value": "t",
                          "domain": ".realtor.ca", "path": "/", "expires": -1,
                          "secure": True, "httpOnly": True, "sameSite": "None"}],
                user_agent="Mozilla/5.0 Chrome/147.0.0.0",
                extras=None, response=None,
            )

        def close(self):
            pass

    solver = _Solver()
    session, client = make_async_session(
        [_imperva_403(), MockResponse(200, body='{"ok": 1}')],
        max_rotations=2, browser_solver=solver, use_cookie_jar=True,
    )
    session._native_tls = FakeNativeTransport([NATIVE_CHALLENGE] * 2)

    with patch("asyncio.sleep", new=AsyncMock()):
        resp = await session.get(URL, headers=HDRS)

    assert resp.status_code == 200
    assert len(solver.solve_calls) == 1  # browser reached, not a lucky rotation
    assert "api2.realtor.ca" not in session._native_tls_domains


@pytest.mark.asyncio
async def test_async_sticky_exhausted_skips_native_with_socks_proxy():
    # A socks proxy can't be tunnelled by the native path, so a fresh Imperva
    # challenge must never probe/pin native -it goes straight to wreq.
    session, client = make_async_session(
        [_imperva_403(), MockResponse(200, body='{"ok": 1}')],
        max_rotations=0,
    )
    session._proxy_url = "socks5://127.0.0.1:9050"
    session._native_tls = FakeNativeTransport([JSON_OK])

    resp = await session.get(URL, headers=HDRS)

    # native never used; the 403 is returned (max_rotations=0, no browser)
    assert len(session._native_tls.calls) == 0
    assert "api2.realtor.ca" not in session._native_tls_domains
    assert resp.challenge_type == "imperva"


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


def test_sync_native_multi_set_cookie_preserved():
    """Native-TLS responses keep EVERY Set-Cookie (reese84 + incap_ses_*),
    not just the first one of the '; '-joined header dict."""
    session, client = make_sync_session([_imperva_403()], max_rotations=0)
    session._native_tls = FakeNativeTransport([JSON_OK_MULTI_COOKIE])

    resp = session.get(URL, headers=HDRS)

    assert resp.status_code == 200
    assert resp.get_all("set-cookie") == MULTI_SET_COOKIE
    assert resp.cookies == {
        "reese84": "tok123",
        "incap_ses_1226_9": "abc",
    }


@pytest.mark.asyncio
async def test_async_native_multi_set_cookie_preserved():
    session, client = make_async_session([_imperva_403()], max_rotations=0)
    session._native_tls = FakeNativeTransport([JSON_OK_MULTI_COOKIE])

    resp = await session.get(URL, headers=HDRS)

    assert resp.status_code == 200
    assert resp.get_all("set-cookie") == MULTI_SET_COOKIE
    assert resp.cookies == {
        "reese84": "tok123",
        "incap_ses_1226_9": "abc",
    }


def test_native_transport_returns_individual_set_cookies():
    """End-to-end over loopback HTTP: NativeTLSTransport.request returns
    the individual Set-Cookie values alongside the joined header dict."""
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    from wafer._native_tls import NativeTLSTransport

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b'{"ok": true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Set-Cookie", "reese84=tok; Path=/")
            self.send_header("Set-Cookie", "incap_ses_1=abc; Path=/")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    srv = HTTPServer(("127.0.0.1", 0), Handler)
    port = srv.server_address[1]
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        t = NativeTLSTransport()
        status, headers, body, final_url, set_cookies = t.request(
            "GET", f"http://127.0.0.1:{port}/x", {"Accept": "*/*"}
        )
        assert status == 200
        assert set_cookies == [
            "reese84=tok; Path=/",
            "incap_ses_1=abc; Path=/",
        ]
        # joined form still present in the flat dict
        assert headers["set-cookie"] == (
            "reese84=tok; Path=/; incap_ses_1=abc; Path=/"
        )
        # both cookies landed in the jar for replay
        assert {c.name for c in t._jar} == {"reese84", "incap_ses_1"}
    finally:
        srv.shutdown()
        thread.join(timeout=5)


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


# ---------------------------------------------------------------------------
# Imperva embedder derivation + browser-solve wiring (Error 15 fix)
# ---------------------------------------------------------------------------


def test_imperva_embedder_derivation():
    pytest.importorskip("wafer.browser")
    from wafer.browser._imperva import imperva_embedder

    # API host called as a same-site XHR -> navigate the real origin page.
    assert imperva_embedder(URL, HDRS) == "https://www.realtor.ca/"
    # A deep Referer collapses to the origin root.
    assert imperva_embedder(
        URL, {"Referer": "https://www.realtor.ca/map/listing/9"}
    ) == "https://www.realtor.ca/"
    # No Referer/Origin: an API subdomain still maps to its www origin.
    assert imperva_embedder(URL, None) == "https://www.realtor.ca/"
    # A normal www page is already navigable -> direct nav (no embedder).
    assert imperva_embedder("https://www.realtor.ca/page", HDRS) is None
    assert imperva_embedder("https://www.amadeus.com/x", None) is None
    # Apex host -> direct nav.
    assert imperva_embedder("https://realtor.ca/x", None) is None
    # A cross-site Referer is ignored; falls back to the www heuristic.
    assert imperva_embedder(
        URL, {"Referer": "https://evil.com/"}
    ) == "https://www.realtor.ca/"


def test_imperva_embedder_hardening():
    pytest.importorskip("wafer.browser")
    from wafer.browser._imperva import imperva_embedder

    # IP-address targets have no registrable domain -> direct nav.
    assert imperva_embedder("https://192.168.1.1/x", None) is None
    assert imperva_embedder("https://[::1]/x", None) is None
    # Referer userinfo + port are stripped (must never reach goto()/logs).
    assert imperva_embedder(
        URL, {"Referer": "https://user:pass@www.realtor.ca:8443/p"}
    ) == "https://www.realtor.ca/"
    # A non-http(s) Referer scheme is ignored -> www heuristic.
    assert imperva_embedder(
        URL, {"Referer": "ftp://www.realtor.ca/"}
    ) == "https://www.realtor.ca/"
    # The embedder scheme follows the TARGET's scheme (no https->http downgrade,
    # no http->https surprise): an http Referer can't downgrade an https target.
    assert imperva_embedder(
        URL, {"Referer": "http://www.realtor.ca/"}
    ) == "https://www.realtor.ca/"
    # An http target keeps http for the embedder.
    assert imperva_embedder(
        "http://api2.realtor.ca/x", {"Referer": "http://www.realtor.ca/"}
    ) == "http://www.realtor.ca/"


def test_registrable_domain_and_cookie_match():
    from wafer._cookies import cookie_domain_matches, registrable_domain

    assert registrable_domain("api2.realtor.ca") == "realtor.ca"
    assert registrable_domain("realtor.ca") == "realtor.ca"
    assert registrable_domain("a.b.c.example.com") == "example.com"
    assert registrable_domain("") == ""
    # Boundary-aware cookie matching.
    assert cookie_domain_matches(".realtor.ca", "realtor.ca")
    assert cookie_domain_matches("api2.realtor.ca", "realtor.ca")
    assert cookie_domain_matches("realtor.ca", "realtor.ca")
    assert not cookie_domain_matches("evil-realtor.ca", "realtor.ca")
    assert not cookie_domain_matches("cloudflare.com", "realtor.ca")
    assert not cookie_domain_matches(".realtor.ca", "")


def test_native_add_cookies_seeds_jar_for_subdomain():
    from urllib.request import Request

    from wafer._native_tls import NativeTLSTransport

    t = NativeTLSTransport()
    t.add_cookies([
        {"name": "reese84", "value": "tok", "domain": ".realtor.ca",
         "path": "/", "secure": True, "expires": -1},
    ])
    # A .realtor.ca cookie must be sent to the api2 subdomain.
    req = Request("https://api2.realtor.ca/Location.svc/X")
    t._jar.add_cookie_header(req)
    assert "reese84=tok" in (req.get_header("Cookie") or "")


def test_imperva_embedder_helper_only_for_imperva():
    from wafer._challenge import ChallengeType

    session, _ = make_sync_session([])
    # Non-Imperva challenge -> no embedder regardless of headers.
    assert session._imperva_embedder(
        ChallengeType.CLOUDFLARE, URL, HDRS, {}
    ) is None
    # No browser solver -> no embedder (nothing to solve with).
    assert session._browser_solver is None
    assert session._imperva_embedder(
        ChallengeType.IMPERVA, URL, HDRS, {}
    ) is None


@pytest.mark.asyncio
async def test_async_browser_solve_uses_embedder_and_seeds_native():
    # The Error 15 fix: when the heavy path reaches the browser solve for an
    # api2 host, it must solve on the www *embedder* (not the API URL), seed
    # the native jar with the earned token, and NOT re-pin native (the retry
    # rides wreq, which carries the token).
    pytest.importorskip("wafer.browser")

    class _Solver:
        def __init__(self):
            self.calls = []

        def solve(self, url, challenge_type=None, timeout=None,
                  embedder=None, replay=None):
            self.calls.append({"url": url, "type": challenge_type,
                               "embedder": embedder})
            return SimpleNamespace(
                cookies=[{"name": "reese84", "value": "t",
                          "domain": ".realtor.ca", "path": "/", "expires": -1,
                          "secure": True, "httpOnly": True, "sameSite": "None"}],
                user_agent="Mozilla/5.0 Chrome/147.0.0.0",
                extras=None, response=None,
            )

        def close(self):
            pass

    solver = _Solver()
    session, client = make_async_session(
        [_imperva_403(), MockResponse(200, body='{"ok": 1}')],
        max_rotations=2, browser_solver=solver, use_cookie_jar=True,
    )
    session._native_tls_domains.add("api2.realtor.ca")
    session._native_tls = FakeNativeTransport([NATIVE_CHALLENGE] * 6)

    with patch("asyncio.sleep", new=AsyncMock()):
        resp = await session.get(URL, headers=HDRS)

    assert resp.status_code == 200
    # Solved on the www embedder, not the API URL.
    assert solver.calls[0]["embedder"] == "https://www.realtor.ca/"
    assert solver.calls[0]["type"] == "imperva"
    # Native jar seeded with the earned token...
    assert any(c["name"] == "reese84" for c in session._native_tls.seeded)
    # ...but the host is left un-pinned (retry rides wreq).
    assert "api2.realtor.ca" not in session._native_tls_domains


@pytest.mark.asyncio
async def test_embedder_solve_keeps_reese84_despite_api_host_cookie():
    # Regression (review High finding): the cookie filter must match the
    # registrable domain, not the exact host. The embedder earns reese84 on
    # .realtor.ca; if an api2.realtor.ca-scoped cookie is ALSO present, a
    # host-exact filter would match only that one, suppress the all-cookies
    # fallback, and silently DROP reese84 from both the wreq jar and native jar.
    pytest.importorskip("wafer.browser")

    class _Solver:
        def solve(self, url, challenge_type=None, timeout=None,
                  embedder=None, replay=None):
            return SimpleNamespace(
                cookies=[
                    {"name": "reese84", "value": "tok",
                     "domain": ".realtor.ca", "path": "/", "expires": -1,
                     "secure": True},
                    # host-scoped cookie that the old filter would match:
                    {"name": "incap_ses_1226_9", "value": "s",
                     "domain": "api2.realtor.ca", "path": "/", "expires": -1,
                     "secure": True},
                ],
                user_agent="Mozilla/5.0 Chrome/147.0.0.0",
                extras=None, response=None,
            )

        def close(self):
            pass

    session, _ = make_async_session(
        [_imperva_403(), MockResponse(200, body='{"ok": 1}')],
        max_rotations=2, browser_solver=_Solver(), use_cookie_jar=True,
    )
    session._native_tls_domains.add("api2.realtor.ca")
    session._native_tls = FakeNativeTransport([NATIVE_CHALLENGE] * 6)

    with patch("asyncio.sleep", new=AsyncMock()):
        await session.get(URL, headers=HDRS)

    seeded = {c["name"] for c in session._native_tls.seeded}
    assert "reese84" in seeded  # the token survived the filter
    assert "incap_ses_1226_9" in seeded


def test_browser_replay_descriptor():
    from wafer._challenge import ChallengeType  # noqa: F401

    session, _ = make_sync_session([])
    # GET: no body.
    r = session._browser_replay("GET", {})
    assert r == {"method": "GET", "body": None, "content_type": None}
    # POST form: urlencoded body + content type, method upper-cased.
    r = session._browser_replay("post", {"form": {"Area": "Ottawa"}})
    assert r["method"] == "POST"
    assert r["body"] == "Area=Ottawa"
    assert r["content_type"] == "application/x-www-form-urlencoded"
    # POST json.
    r = session._browser_replay("POST", {"json": {"a": 1}})
    assert r["content_type"] == "application/json"
    assert r["body"] == '{"a": 1}'
