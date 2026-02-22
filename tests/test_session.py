"""Tests for SyncSession and AsyncSession against httpbin.org."""

import pytest

import wafer
from wafer import AsyncSession, SyncSession


class TestSyncSession:
    def test_get_returns_200(self):
        session = SyncSession()
        resp = session.get("https://httpbin.org/get")
        assert resp.status_code == 200

    def test_get_returns_json_body(self):
        session = SyncSession()
        resp = session.get("https://httpbin.org/get")
        data = resp.json()
        assert data["url"] == "https://httpbin.org/get"

    def test_headers_sent_correctly(self):
        session = SyncSession()
        resp = session.get("https://httpbin.org/headers")
        data = resp.json()
        headers = data["headers"]
        assert "Accept-Language" in headers
        assert headers["Accept-Language"] == "en-US,en;q=0.9"

    def test_request_method_get(self):
        session = SyncSession()
        resp = session.request("GET", "https://httpbin.org/get")
        assert resp.status_code == 200

    def test_context_manager(self):
        with SyncSession() as session:
            resp = session.get("https://httpbin.org/get")
            assert resp.status_code == 200

    def test_module_level_get(self):
        resp = wafer.get("https://httpbin.org/get")
        assert resp.status_code == 200
        data = resp.json()
        assert data["url"] == "https://httpbin.org/get"

    def test_response_has_url(self):
        session = SyncSession()
        resp = session.get("https://httpbin.org/get")
        assert resp.url == "https://httpbin.org/get"

    def test_response_ok(self):
        session = SyncSession()
        resp = session.get("https://httpbin.org/get")
        assert resp.ok is True

    def test_response_text_is_str(self):
        session = SyncSession()
        resp = session.get("https://httpbin.org/get")
        assert isinstance(resp.text, str)
        assert len(resp.text) > 0

    def test_response_headers_is_dict(self):
        session = SyncSession()
        resp = session.get("https://httpbin.org/get")
        assert isinstance(resp.headers, dict)
        assert "content-type" in resp.headers


class TestAsyncSession:
    @pytest.mark.asyncio
    async def test_get_returns_200(self):
        session = AsyncSession()
        resp = await session.get("https://httpbin.org/get")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_get_returns_json_body(self):
        session = AsyncSession()
        resp = await session.get("https://httpbin.org/get")
        data = resp.json()
        assert data["url"] == "https://httpbin.org/get"

    @pytest.mark.asyncio
    async def test_headers_sent_correctly(self):
        session = AsyncSession()
        resp = await session.get("https://httpbin.org/headers")
        data = resp.json()
        headers = data["headers"]
        assert "Accept-Language" in headers
        assert headers["Accept-Language"] == "en-US,en;q=0.9"

    @pytest.mark.asyncio
    async def test_request_method_get(self):
        session = AsyncSession()
        resp = await session.request("GET", "https://httpbin.org/get")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_context_manager(self):
        async with AsyncSession() as session:
            resp = await session.get("https://httpbin.org/get")
            assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_response_has_url(self):
        session = AsyncSession()
        resp = await session.get("https://httpbin.org/get")
        assert resp.url == "https://httpbin.org/get"

    @pytest.mark.asyncio
    async def test_response_ok(self):
        session = AsyncSession()
        resp = await session.get("https://httpbin.org/get")
        assert resp.ok is True
