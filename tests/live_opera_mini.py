"""Live integration tests for Opera Mini profile against search engines.

NOT run in CI — these hit real search engines.
Run manually: uv run pytest tests/live_opera_mini.py -v -s
"""

import re

import pytest

from wafer import AsyncSession, Profile


@pytest.fixture
async def om_session():
    async with AsyncSession(
        profile=Profile.OPERA_MINI,
        max_rotations=0,
        rate_limit=5.0,
        rate_jitter=2.0,
        cache_dir=None,
    ) as session:
        yield session


class TestGoogleSSR:
    """Verify Opera Mini profile triggers Google SSR (server-side rendering)."""

    async def test_google_returns_ssr_html(self, om_session):
        """Google serves SSR HTML with parseable /url?q= result links."""
        resp = await om_session.get(
            "https://www.google.com/search",
            params={
                "q": "python programming",
                "hl": "en",
                "client": "ms-opera-mini-android",
                "channel": "new",
            },
        )
        assert resp.status_code == 200
        assert len(resp.text) > 30000, (
            f"Response too small ({len(resp.text)} bytes) — "
            "likely JS SPA, not SSR"
        )

        url_links = re.findall(r"/url\?q=", resp.text)
        assert len(url_links) >= 5, (
            f"Only {len(url_links)} /url?q= links — expected 10+ for SSR"
        )

        h3_tags = re.findall(r"<h3[^>]*>", resp.text)
        assert len(h3_tags) >= 3, (
            f"Only {len(h3_tags)} <h3> tags — expected 5+ for SSR"
        )

        # Title should contain the search query
        titles = re.findall(r"<title>(.*?)</title>", resp.text)
        assert titles, "No <title> found"
        assert "python" in titles[0].lower(), (
            f"Title doesn't contain query: {titles[0]}"
        )

    async def test_google_not_blocked(self, om_session):
        """Google doesn't block or CAPTCHA the Opera Mini profile."""
        resp = await om_session.get(
            "https://www.google.com/search",
            params={
                "q": "weather today",
                "hl": "en",
                "client": "ms-opera-mini-android",
                "channel": "new",
            },
        )
        assert resp.status_code == 200
        assert "unusual traffic" not in resp.text.lower()
        assert "captcha" not in resp.text.lower()


class TestDDG:
    """Verify Opera Mini profile works with DuckDuckGo HTML endpoint."""

    async def test_ddg_returns_results(self, om_session):
        """DDG HTML endpoint returns parseable search results."""
        resp = await om_session.get(
            "https://html.duckduckgo.com/html/",
            params={"q": "python programming", "kp": "-2"},
            headers={"Accept": "text/html"},
        )
        assert resp.status_code == 200
        result_links = re.findall(r"result__a", resp.text)
        assert len(result_links) >= 5, (
            f"Only {len(result_links)} result__a links — expected 10"
        )


class TestBrave:
    """Verify Opera Mini profile works with Brave Search."""

    async def test_brave_returns_results(self, om_session):
        """Brave Search returns parseable results."""
        resp = await om_session.get(
            "https://search.brave.com/search",
            params={"q": "python programming"},
        )
        assert resp.status_code == 200
        data_pos = re.findall(r"data-pos", resp.text)
        assert len(data_pos) >= 5, (
            f"Only {len(data_pos)} data-pos results — expected 10+"
        )


class TestHeaders:
    """Verify Opera Mini headers are clean (no Chrome header leakage)."""

    async def test_no_chrome_headers(self, om_session):
        """No Sec-Ch-Ua or Sec-Fetch-* headers should be present."""
        resp = await om_session.get("https://httpbin.org/headers")
        import json
        headers = json.loads(resp.text)["headers"]

        # Chrome headers should NOT be present
        chrome_headers = [
            "Sec-Ch-Ua", "Sec-Ch-Ua-Mobile", "Sec-Ch-Ua-Platform",
            "Sec-Fetch-Dest", "Sec-Fetch-Mode", "Sec-Fetch-Site",
        ]
        for h in chrome_headers:
            assert h not in headers, (
                f"Chrome header {h} is leaking: {headers[h]}"
            )

    async def test_opera_mini_headers_present(self, om_session):
        """All Opera Mini headers should be present."""
        resp = await om_session.get("https://httpbin.org/headers")
        import json
        headers = json.loads(resp.text)["headers"]

        assert "Opera Mini" in headers.get("User-Agent", "")
        assert "Presto" in headers.get("User-Agent", "")
        assert headers.get("X-Operamini-Features")
        assert headers.get("X-Operamini-Phone")
        assert headers.get("X-Operamini-Phone-Ua")
        assert headers.get("Device-Stock-Ua")
        assert "deflate" in headers.get("Accept-Encoding", "")
