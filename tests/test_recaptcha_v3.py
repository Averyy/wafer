"""Tests for browser-free reCAPTCHA v3 token minting.

Covers the pure helpers (co encoding, cb generation, regex scrapes) and
the sync/async mint flows driven by a fake recording request callable,
plus session-method wiring and v caching via the mock-client factories.
"""

import asyncio
import os
import urllib.parse

import pytest

from tests.conftest import (
    AsyncMockResponse,
    MockResponse,
    make_async_session,
    make_sync_session,
)
from wafer import TokenMintFailed
from wafer import _recaptcha_v3 as rc

# A realistic anchor page snippet carrying the hidden recaptcha-token input.
ANCHOR_HTML = (
    '<html><body><input type="hidden" id="recaptcha-token" '
    'value="ANCHOR_C_TOKEN_abc123"></body></html>'
)
# A realistic reload body fragment carrying the final rresp token.
RELOAD_BODY = ')]}\'\n["rresp","03AGdFINAL_TOKEN_xyz789",null,120,1]'
# A realistic api.js loader fragment carrying the release hash.
API_JS = (
    "var w=window;...po.src='https://www.gstatic.com/recaptcha/"
    "releases/ne1iDVwClkE7nKD3uA9Vqsvl/recaptcha__en.js';po.crossOrigin"
)

SITEKEY = "6LdyC2cUAAAAACGuDKpXeDorzUDWXmdqeg-xy696"
ORIGIN = "https://www.example.com"


class Recorder:
    """A fake request callable that returns queued responses and records calls.

    Each queued item is (status_code, body). Calls are recorded as
    (method, url, kwargs) tuples for assertion.
    """

    def __init__(self, queue):
        self._queue = list(queue)
        self.calls = []

    def __call__(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        status, body = self._queue.pop(0)
        return _FakeResp(status, body)

    async def acall(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        status, body = self._queue.pop(0)
        return _FakeResp(status, body)


class _FakeResp:
    def __init__(self, status_code, text):
        self.status_code = status_code
        self.text = text


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


class TestComputeCo:
    def test_bell_origin_matches_known_co(self):
        # Exact format bell uses: base64url(origin + ":443") with '=' -> '.'
        assert (
            rc.compute_co("https://www.bell.ca")
            == "aHR0cHM6Ly93d3cuYmVsbC5jYTo0NDM."
        )

    def test_decodes_back_to_origin_with_port(self):
        co = rc.compute_co(ORIGIN)
        # Reverse: '.' -> '=' padding, then urlsafe b64decode.
        raw = co.replace(".", "=")
        assert urllib.parse.unquote(
            __import__("base64").urlsafe_b64decode(raw).decode()
        ) == "https://www.example.com:443"

    def test_strips_path_and_query(self):
        assert rc.compute_co(
            "https://www.example.com/page?x=1"
        ) == rc.compute_co("https://www.example.com")

    def test_bare_host_assumes_https(self):
        assert rc.compute_co("www.example.com") == rc.compute_co(
            "https://www.example.com"
        )


class TestGenerateCb:
    def test_length_is_18(self):
        assert len(rc.generate_cb()) == 18

    def test_alphanumeric_only(self):
        cb = rc.generate_cb()
        assert all(c in rc._CB_ALPHABET for c in cb)

    def test_deterministic_with_seed(self):
        seed = bytes(range(18))
        assert rc.generate_cb(seed) == rc.generate_cb(seed)

    def test_varies_across_calls(self):
        # os.urandom-backed: two calls should (essentially always) differ.
        assert rc.generate_cb() != rc.generate_cb()

    def test_short_seed_is_padded(self):
        assert len(rc.generate_cb(b"\x00")) == 18


class TestOriginFromReferer:
    def test_extracts_scheme_and_host(self):
        assert (
            rc.origin_from_referer("https://www.example.com/login?a=1")
            == "https://www.example.com"
        )

    def test_preserves_explicit_port(self):
        assert (
            rc.origin_from_referer("https://example.com:8443/x")
            == "https://example.com:8443"
        )

    def test_bare_string_raises(self):
        with pytest.raises(TokenMintFailed):
            rc.origin_from_referer("not-a-url")


class TestParseAnchorToken:
    def test_scrapes_token(self):
        assert (
            rc.parse_anchor_token(ANCHOR_HTML, 200)
            == "ANCHOR_C_TOKEN_abc123"
        )

    def test_name_attribute_variant(self):
        html = '<input name="recaptcha-token" value="TOK2">'
        assert rc.parse_anchor_token(html, 200) == "TOK2"

    def test_missing_raises_with_stage(self):
        with pytest.raises(TokenMintFailed) as ei:
            rc.parse_anchor_token("<html>no token</html>", 403)
        assert ei.value.stage == "anchor"
        assert ei.value.status_code == 403


class TestParseReloadToken:
    def test_scrapes_token(self):
        assert (
            rc.parse_reload_token(RELOAD_BODY, 200)
            == "03AGdFINAL_TOKEN_xyz789"
        )

    def test_missing_raises_with_stage(self):
        with pytest.raises(TokenMintFailed) as ei:
            rc.parse_reload_token('["wrong","x"]', 200)
        assert ei.value.stage == "reload"


class TestParseReleaseVersion:
    def test_scrapes_version(self):
        assert (
            rc.parse_release_version(API_JS) == "ne1iDVwClkE7nKD3uA9Vqsvl"
        )

    def test_missing_raises(self):
        with pytest.raises(TokenMintFailed) as ei:
            rc.parse_release_version("no release here")
        assert ei.value.stage == "apijs"


class TestUrlBuilders:
    def test_anchor_url_standard(self):
        url = rc.build_anchor_url(
            SITEKEY, co="CO", v="VVV", cb="CB", enterprise=False
        )
        assert url.startswith(
            "https://www.google.com/recaptcha/api2/anchor?"
        )
        q = urllib.parse.parse_qs(url.split("?", 1)[1])
        assert q["k"] == [SITEKEY]
        assert q["co"] == ["CO"]
        assert q["v"] == ["VVV"]
        assert q["cb"] == ["CB"]
        assert q["size"] == ["invisible"]
        assert q["ar"] == ["1"]
        assert q["hl"] == ["en"]

    def test_anchor_url_enterprise_path(self):
        url = rc.build_anchor_url(
            SITEKEY, co="CO", v="V", cb="CB", enterprise=True
        )
        assert "/recaptcha/enterprise/anchor?" in url

    def test_reload_url_standard(self):
        assert rc.build_reload_url(SITEKEY) == (
            "https://www.google.com/recaptcha/api2/reload?k="
            + urllib.parse.quote(SITEKEY)
        )

    def test_reload_url_enterprise(self):
        assert "/recaptcha/enterprise/reload?k=" in rc.build_reload_url(
            SITEKEY, enterprise=True
        )

    def test_reload_body_carries_action_in_sa(self):
        body = rc.build_reload_body(
            SITEKEY, co="CO", v="V", action="login", anchor_token="AT"
        )
        q = urllib.parse.parse_qs(body)
        assert q["sa"] == ["login"]
        assert q["c"] == ["AT"]
        assert q["reason"] == ["q"]
        assert q["k"] == [SITEKEY]
        assert q["size"] == ["invisible"]
        assert "chr" not in q  # action rides in sa, not chr

    def test_apijs_url_modes(self):
        assert rc.apijs_url(False).endswith("/recaptcha/api.js")
        assert rc.apijs_url(True).endswith("/recaptcha/enterprise.js")


# ---------------------------------------------------------------------------
# Sync mint flow (fake recorder)
# ---------------------------------------------------------------------------


class TestMintSync:
    def test_full_flow_with_explicit_v(self):
        rec = Recorder([(200, ANCHOR_HTML), (200, RELOAD_BODY)])
        token = rc.mint_sync(
            rec, SITEKEY, "login", origin=ORIGIN, v="VVV"
        )
        assert token == "03AGdFINAL_TOKEN_xyz789"
        # Two calls: anchor GET, reload POST (no api.js fetch -- v given).
        assert len(rec.calls) == 2

        m1, u1, k1 = rec.calls[0]
        assert m1 == "GET"
        assert u1.startswith(
            "https://www.google.com/recaptcha/api2/anchor?"
        )
        assert k1["headers"]["Referer"] == ORIGIN

        m2, u2, k2 = rec.calls[1]
        assert m2 == "POST"
        assert u2.startswith(
            "https://www.google.com/recaptcha/api2/reload?k="
        )
        assert k2["headers"]["Origin"] == "https://www.google.com"
        assert k2["headers"]["Referer"] == u1  # referer is the anchor url
        assert (
            k2["headers"]["Content-Type"]
            == "application/x-www-form-urlencoded"
        )
        body_q = urllib.parse.parse_qs(k2["body"])
        assert body_q["c"] == ["ANCHOR_C_TOKEN_abc123"]
        assert body_q["sa"] == ["login"]
        assert body_q["v"] == ["VVV"]

    def test_co_in_anchor_matches_origin(self):
        rec = Recorder([(200, ANCHOR_HTML), (200, RELOAD_BODY)])
        rc.mint_sync(rec, SITEKEY, "act", origin=ORIGIN, v="V")
        _, anchor_url, _ = rec.calls[0]
        q = urllib.parse.parse_qs(anchor_url.split("?", 1)[1])
        assert q["co"] == [rc.compute_co(ORIGIN)]

    def test_referer_defaults_to_origin(self):
        rec = Recorder([(200, ANCHOR_HTML), (200, RELOAD_BODY)])
        rc.mint_sync(rec, SITEKEY, "act", origin=ORIGIN, v="V")
        assert rec.calls[0][2]["headers"]["Referer"] == ORIGIN

    def test_origin_derived_from_referer(self):
        rec = Recorder([(200, ANCHOR_HTML), (200, RELOAD_BODY)])
        rc.mint_sync(
            rec,
            SITEKEY,
            "act",
            referer="https://shop.example.com/checkout",
            v="V",
        )
        _, anchor_url, k = rec.calls[0]
        q = urllib.parse.parse_qs(anchor_url.split("?", 1)[1])
        assert q["co"] == [rc.compute_co("https://shop.example.com")]
        # Referer header is the full referer the caller passed.
        assert k["headers"]["Referer"] == "https://shop.example.com/checkout"

    def test_enterprise_uses_enterprise_paths(self):
        rec = Recorder([(200, ANCHOR_HTML), (200, RELOAD_BODY)])
        rc.mint_sync(
            rec, SITEKEY, "act", origin=ORIGIN, v="V", enterprise=True
        )
        assert "/recaptcha/enterprise/anchor?" in rec.calls[0][1]
        assert "/recaptcha/enterprise/reload?k=" in rec.calls[1][1]

    def test_scrapes_v_when_not_given(self):
        # api.js GET, then anchor GET, then reload POST.
        rec = Recorder(
            [(200, API_JS), (200, ANCHOR_HTML), (200, RELOAD_BODY)]
        )
        rc.mint_sync(rec, SITEKEY, "act", origin=ORIGIN)
        assert len(rec.calls) == 3
        assert rec.calls[0][1].endswith("/recaptcha/api.js")
        anchor_q = urllib.parse.parse_qs(
            rec.calls[1][1].split("?", 1)[1]
        )
        assert anchor_q["v"] == ["ne1iDVwClkE7nKD3uA9Vqsvl"]

    def test_missing_anchor_token_raises(self):
        rec = Recorder([(200, "<html>blocked</html>"), (200, RELOAD_BODY)])
        with pytest.raises(TokenMintFailed) as ei:
            rc.mint_sync(rec, SITEKEY, "act", origin=ORIGIN, v="V")
        assert ei.value.stage == "anchor"

    def test_missing_reload_token_raises(self):
        rec = Recorder([(200, ANCHOR_HTML), (200, "garbage")])
        with pytest.raises(TokenMintFailed) as ei:
            rc.mint_sync(rec, SITEKEY, "act", origin=ORIGIN, v="V")
        assert ei.value.stage == "reload"

    def test_no_origin_or_referer_raises(self):
        rec = Recorder([])
        with pytest.raises(TokenMintFailed):
            rc.mint_sync(rec, SITEKEY, "act", v="V")


# ---------------------------------------------------------------------------
# Async mint flow (fake recorder)
# ---------------------------------------------------------------------------


class TestMintAsync:
    def test_full_flow(self):
        rec = Recorder([(200, ANCHOR_HTML), (200, RELOAD_BODY)])
        token = asyncio.run(
            rc.mint_async(rec.acall, SITEKEY, "login", origin=ORIGIN, v="V")
        )
        assert token == "03AGdFINAL_TOKEN_xyz789"
        assert [c[0] for c in rec.calls] == ["GET", "POST"]

    def test_scrapes_v(self):
        rec = Recorder(
            [(200, API_JS), (200, ANCHOR_HTML), (200, RELOAD_BODY)]
        )
        asyncio.run(
            rc.mint_async(rec.acall, SITEKEY, "act", origin=ORIGIN)
        )
        assert rec.calls[0][1].endswith("/recaptcha/api.js")

    def test_missing_reload_token_raises(self):
        rec = Recorder([(200, ANCHOR_HTML), (200, "garbage")])
        with pytest.raises(TokenMintFailed):
            asyncio.run(
                rc.mint_async(
                    rec.acall, SITEKEY, "act", origin=ORIGIN, v="V"
                )
            )


# ---------------------------------------------------------------------------
# Session-method wiring + v caching (mock-client factory)
# ---------------------------------------------------------------------------


class TestSessionSyncWiring:
    def test_method_returns_token_and_caches_v(self):
        # api.js, anchor, reload  -> first mint scrapes v
        session, _ = make_sync_session(
            [
                MockResponse(200, {"content-type": "text/javascript"}, API_JS),
                MockResponse(200, {"content-type": "text/html"}, ANCHOR_HTML),
                MockResponse(
                    200, {"content-type": "application/json"}, RELOAD_BODY
                ),
            ]
        )
        token = session.mint_recaptcha_v3(SITEKEY, "login", origin=ORIGIN)
        assert token == "03AGdFINAL_TOKEN_xyz789"
        assert session._recaptcha_v == {"std": "ne1iDVwClkE7nKD3uA9Vqsvl"}

    def test_second_call_reuses_cached_v(self):
        # Only 2 responses queued (anchor, reload) -- no api.js fetch the
        # second time because v is cached. Pre-seed the cache.
        session, _ = make_sync_session(
            [
                MockResponse(200, {"content-type": "text/html"}, ANCHOR_HTML),
                MockResponse(
                    200, {"content-type": "application/json"}, RELOAD_BODY
                ),
            ]
        )
        session._recaptcha_v["std"] = "CACHED_V"
        token = session.mint_recaptcha_v3(SITEKEY, "submit", origin=ORIGIN)
        assert token == "03AGdFINAL_TOKEN_xyz789"

    def test_explicit_v_skips_apijs_fetch(self):
        session, _ = make_sync_session(
            [
                MockResponse(200, {"content-type": "text/html"}, ANCHOR_HTML),
                MockResponse(
                    200, {"content-type": "application/json"}, RELOAD_BODY
                ),
            ]
        )
        token = session.mint_recaptcha_v3(
            SITEKEY, "act", origin=ORIGIN, v="MYV"
        )
        assert token == "03AGdFINAL_TOKEN_xyz789"
        assert session._recaptcha_v == {}

    def test_missing_token_raises(self):
        session, _ = make_sync_session(
            [
                MockResponse(
                    200, {"content-type": "text/html"}, "<html>none</html>"
                ),
            ]
        )
        with pytest.raises(TokenMintFailed):
            session.mint_recaptcha_v3(SITEKEY, "act", origin=ORIGIN, v="V")


class TestSessionAsyncWiring:
    def test_method_returns_token(self):
        session, _ = make_async_session(
            [
                AsyncMockResponse(
                    200, {"content-type": "text/javascript"}, API_JS
                ),
                AsyncMockResponse(
                    200, {"content-type": "text/html"}, ANCHOR_HTML
                ),
                AsyncMockResponse(
                    200, {"content-type": "application/json"}, RELOAD_BODY
                ),
            ]
        )
        token = asyncio.run(
            session.mint_recaptcha_v3(SITEKEY, "login", origin=ORIGIN)
        )
        assert token == "03AGdFINAL_TOKEN_xyz789"
        assert session._recaptcha_v == {"std": "ne1iDVwClkE7nKD3uA9Vqsvl"}


# ---------------------------------------------------------------------------
# Live test (network) -- mints against Google's reCAPTCHA v3 demo sitekey.
# ---------------------------------------------------------------------------


@pytest.mark.live
@pytest.mark.skipif(
    os.environ.get("WAFER_LIVE") != "1",
    reason="live network test; set WAFER_LIVE=1 to run",
)
def test_live_mint_against_google_demo():
    """Mint a real token using Google's public reCAPTCHA v3 demo sitekey.

    Demo: https://www.google.com/recaptcha/api2/demo (v3 invisible). The
    sitekey below is Google's own public v3 demo key, bound to
    www.google.com. Confirms a non-empty token comes back end-to-end.
    """
    import wafer

    with wafer.SyncSession() as session:
        token = session.mint_recaptcha_v3(
            "6LdyC2cUAAAAACGuDKpXeDorzUDWXmdqeg-xy696",
            "login",
            origin="https://www.google.com",
        )
    assert isinstance(token, str)
    assert len(token) > 100
