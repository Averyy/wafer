"""Tests for the max_response_size cap (E9) and ResponseTooLarge."""

import asyncio
from unittest.mock import patch

import pytest

from tests.conftest import (
    AsyncMockResponse,
    MockResponse,
    _MockStreamer,
    make_async_session,
    make_sync_session,
)
from wafer import ResponseTooLarge, WaferError
from wafer._base import (
    _aread_body_capped,
    _CapExceeded,
    _content_length_over_cap,
    _read_body_capped,
)


class _FakeResp:
    """Minimal stand-in for a wreq Response (content_length + stream())."""

    def __init__(self, body: bytes, content_length=None, chunk_size=16):
        self._body = body
        self.content_length = content_length
        self._chunk_size = chunk_size

    def stream(self):
        return _MockStreamer(self._body, chunk_size=self._chunk_size)


class TestHelpers:
    def test_content_length_over_cap_returns_declared(self):
        r = _FakeResp(b"", content_length=5000)
        assert _content_length_over_cap(r, 500) == 5000

    def test_content_length_within_cap_returns_none(self):
        r = _FakeResp(b"", content_length=300)
        assert _content_length_over_cap(r, 500) is None

    def test_content_length_none_returns_none(self):
        r = _FakeResp(b"", content_length=None)
        assert _content_length_over_cap(r, 500) is None

    def test_content_length_zero_returns_none(self):
        # Chunked responses report 0; must fall through to streamed read.
        r = _FakeResp(b"", content_length=0)
        assert _content_length_over_cap(r, 500) is None

    def test_read_body_capped_under_cap(self):
        r = _FakeResp(b"hello world", chunk_size=4)
        assert _read_body_capped(r, 100) == b"hello world"

    def test_read_body_capped_over_cap_raises(self):
        r = _FakeResp(b"x" * 100, chunk_size=16)
        with pytest.raises(_CapExceeded) as ei:
            _read_body_capped(r, 50)
        # Early-abort: stops shortly after passing the cap, not at the end.
        assert ei.value.size > 50
        assert ei.value.size <= 50 + 16  # at most one chunk past the cap

    def test_read_body_capped_exact_cap_ok(self):
        r = _FakeResp(b"x" * 50, chunk_size=10)
        # len == cap is allowed (only > cap raises).
        assert _read_body_capped(r, 50) == b"x" * 50

    def test_aread_body_capped_under_cap(self):
        r = _FakeResp(b"hello", chunk_size=2)
        assert asyncio.run(_aread_body_capped(r, 100)) == b"hello"

    def test_aread_body_capped_over_cap_raises(self):
        r = _FakeResp(b"y" * 80, chunk_size=8)
        with pytest.raises(_CapExceeded):
            asyncio.run(_aread_body_capped(r, 30))


class TestSyncSessionCap:
    @patch("time.sleep")
    def test_under_cap_passes(self, _sleep):
        session, _ = make_sync_session(
            [MockResponse(200, body="small body")],
            max_response_size=1000,
        )
        resp = session.get("https://example.com/")
        assert resp.status_code == 200
        assert resp.text == "small body"

    @patch("time.sleep")
    def test_over_cap_streamed_raises(self, _sleep):
        body = "z" * 5000
        session, _ = make_sync_session(
            [MockResponse(200, body=body)],
            max_response_size=500,
        )
        with pytest.raises(ResponseTooLarge) as ei:
            session.get("https://example.com/")
        assert ei.value.limit == 500
        assert ei.value.size > 500
        assert ei.value.url == "https://example.com/"

    @patch("time.sleep")
    def test_over_cap_content_length_short_circuit(self, _sleep):
        # Declared Content-Length over the cap raises before any body read.
        session, _ = make_sync_session(
            [MockResponse(200, body="ignored", content_length=999999)],
            max_response_size=500,
        )
        with pytest.raises(ResponseTooLarge) as ei:
            session.get("https://example.com/")
        assert ei.value.size == 999999
        assert ei.value.limit == 500

    @patch("time.sleep")
    def test_response_too_large_is_wafer_error(self, _sleep):
        session, _ = make_sync_session(
            [MockResponse(200, body="z" * 5000)],
            max_response_size=100,
        )
        with pytest.raises(WaferError):
            session.get("https://example.com/")

    @patch("time.sleep")
    def test_per_request_override_tighter(self, _sleep):
        # Session cap is generous; a tighter per-request cap raises.
        session, _ = make_sync_session(
            [MockResponse(200, body="z" * 5000)],
            max_response_size=1_000_000,
        )
        with pytest.raises(ResponseTooLarge):
            session.get("https://example.com/", max_response_size=500)

    @patch("time.sleep")
    def test_per_request_override_looser(self, _sleep):
        # Session cap is tight; a looser per-request cap lets it through.
        session, _ = make_sync_session(
            [MockResponse(200, body="z" * 5000)],
            max_response_size=100,
        )
        resp = session.get(
            "https://example.com/", max_response_size=1_000_000
        )
        assert resp.status_code == 200
        assert len(resp.content) == 5000

    @patch("time.sleep")
    def test_default_none_unchanged(self, _sleep):
        # No cap: a large body passes through untouched.
        body = "q" * 200_000
        session, _ = make_sync_session([MockResponse(200, body=body)])
        resp = session.get("https://example.com/")
        assert resp.status_code == 200
        assert len(resp.content) == 200_000

    @patch("time.sleep")
    def test_per_request_max_not_forwarded_to_wreq(self, _sleep):
        # max_response_size is consumed by request(), never leaked to wreq.
        session, mock = make_sync_session(
            [MockResponse(200, body="ok")],
        )
        session.get("https://example.com/", max_response_size=1000)
        assert "max_response_size" not in mock.last_kwargs


class TestAsyncSessionCap:
    @patch("time.sleep")
    def test_under_cap_passes(self, _sleep):
        async def run():
            session, _ = make_async_session(
                [AsyncMockResponse(200, body="small")],
                max_response_size=1000,
            )
            return await session.get("https://example.com/")

        resp = asyncio.run(run())
        assert resp.status_code == 200
        assert resp.text == "small"

    @patch("time.sleep")
    def test_over_cap_streamed_raises(self, _sleep):
        async def run():
            session, _ = make_async_session(
                [AsyncMockResponse(200, body="z" * 5000)],
                max_response_size=500,
            )
            return await session.get("https://example.com/")

        with pytest.raises(ResponseTooLarge) as ei:
            asyncio.run(run())
        assert ei.value.limit == 500

    @patch("time.sleep")
    def test_over_cap_content_length_short_circuit(self, _sleep):
        async def run():
            session, _ = make_async_session(
                [
                    AsyncMockResponse(
                        200, body="ignored", content_length=999999
                    )
                ],
                max_response_size=500,
            )
            return await session.get("https://example.com/")

        with pytest.raises(ResponseTooLarge) as ei:
            asyncio.run(run())
        assert ei.value.size == 999999

    @patch("time.sleep")
    def test_per_request_override(self, _sleep):
        async def run():
            session, _ = make_async_session(
                [AsyncMockResponse(200, body="z" * 5000)],
                max_response_size=1_000_000,
            )
            return await session.get(
                "https://example.com/", max_response_size=500
            )

        with pytest.raises(ResponseTooLarge):
            asyncio.run(run())

    @patch("time.sleep")
    def test_default_none_unchanged(self, _sleep):
        async def run():
            session, _ = make_async_session(
                [AsyncMockResponse(200, body="q" * 200_000)]
            )
            return await session.get("https://example.com/")

        resp = asyncio.run(run())
        assert len(resp.content) == 200_000
