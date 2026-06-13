"""Tests for SyncSession and AsyncSession with mocked wreq client."""

import json

import pytest

import wafer
from tests.conftest import (
    AsyncMockResponse,
    MockResponse,
    make_async_session,
    make_sync_session,
)

BODY_JSON = json.dumps({"url": "https://example.com/get", "data": "hello"})
OK = {"content-type": "text/html"}
OK_BODY = "<html><body>ok</body></html>"


def ok_response(status=200, headers=None, body=OK_BODY):
    return MockResponse(status, headers or dict(OK), body)


class TestSyncSession:
    def test_get_returns_status_code(self):
        session, _ = make_sync_session([ok_response()])
        resp = session.get("https://example.com/get")
        assert resp.status_code == 200

    def test_get_non_200_status(self):
        session, _ = make_sync_session([ok_response(404)])
        resp = session.get("https://example.com/missing")
        assert resp.status_code == 404
        assert resp.ok is False

    def test_json_body_parsed(self):
        session, _ = make_sync_session([
            ok_response(headers={"content-type": "application/json"},
                        body=BODY_JSON),
        ])
        resp = session.get("https://example.com/get")
        data = resp.json()
        assert data["url"] == "https://example.com/get"
        assert data["data"] == "hello"

    def test_text_is_str(self):
        session, _ = make_sync_session([ok_response(body="plain text body")])
        resp = session.get("https://example.com")
        assert isinstance(resp.text, str)
        assert resp.text == "plain text body"

    def test_response_url_matches_request(self):
        session, _ = make_sync_session([ok_response()])
        resp = session.get("https://example.com/page")
        assert resp.url == "https://example.com/page"

    def test_response_ok_true_for_2xx(self):
        session, _ = make_sync_session([ok_response(201)])
        resp = session.get("https://example.com")
        assert resp.ok is True

    def test_response_ok_false_for_4xx(self):
        session, _ = make_sync_session(
            [ok_response(403)], max_rotations=0,
        )
        resp = session.get("https://example.com")
        assert resp.ok is False

    def test_response_headers_is_dict(self):
        session, _ = make_sync_session([
            ok_response(headers={"content-type": "text/html", "x-custom": "val"}),
        ])
        resp = session.get("https://example.com")
        assert isinstance(resp.headers, dict)
        assert resp.headers["content-type"] == "text/html"
        assert resp.headers["x-custom"] == "val"

    def test_default_headers_sent(self):
        """Session sends Accept-Language and other defaults to wreq."""
        session, mock = make_sync_session([ok_response()])
        session.get("https://example.com")
        # Default headers are set at client level, so per-request delta
        # should NOT contain them (that would cause HTTP/2 duplication).
        # But session.headers should contain the defaults.
        assert session.headers["Accept-Language"] == "en-US,en;q=0.9"
        assert "Accept-Encoding" in session.headers

    def test_request_method_get(self):
        session, mock = make_sync_session([ok_response()])
        session.request("GET", "https://example.com")
        method, url, _ = mock.request_log[0]
        assert "GET" in str(method)

    def test_context_manager(self):
        session, _ = make_sync_session([ok_response()])
        with session:
            resp = session.get("https://example.com")
            assert resp.status_code == 200

    def test_request_count_increments(self):
        session, mock = make_sync_session([ok_response(), ok_response()])
        session.get("https://example.com/a")
        session.get("https://example.com/b")
        assert mock.request_count == 2


class TestAsyncSession:
    @pytest.mark.asyncio
    async def test_get_returns_status_code(self):
        session, _ = make_async_session([ok_response()])
        resp = await session.get("https://example.com/get")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_get_non_200_status(self):
        session, _ = make_async_session([ok_response(404)])
        resp = await session.get("https://example.com/missing")
        assert resp.status_code == 404
        assert resp.ok is False

    @pytest.mark.asyncio
    async def test_json_body_parsed(self):
        session, _ = make_async_session([
            ok_response(headers={"content-type": "application/json"},
                        body=BODY_JSON),
        ])
        resp = await session.get("https://example.com/get")
        data = resp.json()
        assert data["url"] == "https://example.com/get"

    @pytest.mark.asyncio
    async def test_response_url_matches_request(self):
        session, _ = make_async_session([ok_response()])
        resp = await session.get("https://example.com/page")
        assert resp.url == "https://example.com/page"

    @pytest.mark.asyncio
    async def test_response_ok_true_for_2xx(self):
        session, _ = make_async_session([ok_response(201)])
        resp = await session.get("https://example.com")
        assert resp.ok is True

    @pytest.mark.asyncio
    async def test_response_headers_is_dict(self):
        session, _ = make_async_session([
            ok_response(headers={"content-type": "text/html"}),
        ])
        resp = await session.get("https://example.com")
        assert isinstance(resp.headers, dict)
        assert resp.headers["content-type"] == "text/html"

    @pytest.mark.asyncio
    async def test_default_headers_on_session(self):
        session, _ = make_async_session([ok_response()])
        await session.get("https://example.com")
        assert session.headers["Accept-Language"] == "en-US,en;q=0.9"

    @pytest.mark.asyncio
    async def test_request_method_get(self):
        session, mock = make_async_session([ok_response()])
        await session.request("GET", "https://example.com")
        method, _, _ = mock.request_log[0]
        assert "GET" in str(method)

    @pytest.mark.asyncio
    async def test_context_manager(self):
        session, _ = make_async_session([ok_response()])
        async with session:
            resp = await session.get("https://example.com")
            assert resp.status_code == 200


class _BytesBodyResponse(MockResponse):
    """MockResponse whose bytes() returns arbitrary raw bytes.

    Mirrors a real wreq response for non-utf-8 bodies: bytes() is the
    decompressed wire body, in whatever encoding the server used.
    """

    def __init__(self, status_code, headers, raw: bytes):
        super().__init__(status_code, headers, raw.decode("utf-8", "replace"))
        self._raw_bytes = raw

    def bytes(self):
        return self._raw_bytes


class _AsyncBytesBodyResponse(AsyncMockResponse):
    def __init__(self, status_code, headers, raw: bytes):
        super().__init__(status_code, headers, raw.decode("utf-8", "replace"))
        self._raw_bytes = raw

    async def bytes(self):
        return self._raw_bytes


WIN1252_HTML = (
    '<html><head><meta charset="windows-1252"></head>'
    "<body>café — “quotes”</body></html>"
)


class TestWreqPathCharset:
    """The main wreq path must be charset-aware and keep true body bytes.

    wreq's own text() never sniffs <meta charset>, so wafer reads the
    decompressed bytes() and decodes them itself (header charset ->
    meta sniff -> utf-8).
    """

    def test_sync_meta_charset_decoded_on_wreq_path(self):
        raw = WIN1252_HTML.encode("windows-1252")
        session, _ = make_sync_session([
            _BytesBodyResponse(200, {"content-type": "text/html"}, raw),
        ])
        resp = session.get("https://example.com")
        assert "café" in resp.text
        assert "“quotes”" in resp.text
        # content is the true wire bytes, not a lossy utf-8 re-encode
        assert resp.content == raw

    @pytest.mark.asyncio
    async def test_async_meta_charset_decoded_on_wreq_path(self):
        raw = WIN1252_HTML.encode("windows-1252")
        session, _ = make_async_session([
            _AsyncBytesBodyResponse(
                200, {"content-type": "text/html"}, raw
            ),
        ])
        resp = await session.get("https://example.com")
        assert "café" in resp.text
        assert "“quotes”" in resp.text
        assert resp.content == raw

    def test_sync_header_charset_decoded_on_wreq_path(self):
        raw = "héllo".encode("latin-1")
        session, _ = make_sync_session([
            _BytesBodyResponse(
                200, {"content-type": "text/html; charset=latin-1"}, raw
            ),
        ])
        resp = session.get("https://example.com")
        assert resp.text == "héllo"
        assert resp.content == raw

    def test_sync_utf8_body_byte_identical(self):
        """The common utf-8 case must stay byte-identical."""
        body = "<html><body>café é中文</body></html>"
        session, _ = make_sync_session([
            MockResponse(200, {"content-type": "text/html"}, body),
        ])
        resp = session.get("https://example.com")
        assert resp.text == body
        assert resp.content == body.encode("utf-8")


class TestModuleLevelGet:
    def test_module_get_returns_response(self, monkeypatch):
        """wafer.get() creates a SyncSession and returns a WaferResponse."""
        from wafer._response import WaferResponse

        fake_resp = WaferResponse(
            status_code=200,
            headers={"content-type": "text/html"},
            url="https://example.com",
            text="ok",
        )

        class FakeSession:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                pass

            def get(self, url, **kwargs):
                return fake_resp

        monkeypatch.setattr(wafer, "SyncSession", lambda **kw: FakeSession())
        resp = wafer.get("https://example.com")
        assert resp.status_code == 200
        assert resp.text == "ok"
