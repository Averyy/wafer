"""Focused offline coverage for SearchGuard cookie and retry wiring."""

import asyncio
import datetime
import json

import pytest

from tests.conftest import MockResponse, make_async_session, make_sync_session
from wafer import AsyncSession, SyncSession
from wafer._challenge import ChallengeType

_TOKEN = "abcdefghijklmnopqrstuvwxyz0123456789"


def test_searchguard_runtime_exposes_vm_dom_and_location_inputs():
    quickjs = pytest.importorskip("quickjs")
    from urllib.parse import urlparse

    from wafer._searchguard import _SHIM, _js_quote_url_parts

    context = quickjs.Context()
    url = "https://www.google.com/search?q=knits#results"
    inputs = {
        "__waferHref": url,
        "__waferSearch": "?q=knits",
        "__waferUA": "",
        "__waferInitialCookie": "",
        "__waferCores": 1,
        "__waferPlatform": "MacIntel",
        "__waferIsChromium": True,
        "__waferURLParts": json.loads(_js_quote_url_parts(urlparse(url))),
    }
    for name, value in inputs.items():
        if isinstance(value, dict):
            value = context.parse_json(json.dumps(value))
        context.set(name, value)
    native_now = context.eval("performance.now.toString()")
    context.eval(_SHIM)

    assert json.loads(context.eval("""JSON.stringify([
        document.location.protocol, document.location.hostname,
        document.location.pathname, document.location.hash, String(location)
    ])""")) == ["https:", "www.google.com", "/search", "#results", url]
    assert context.eval("""
        const frame = document.createElement('iframe').contentWindow;
        frame.Object.getOwnPropertyNames(frame.Object).includes('getOwnPropertyNames')
    """)
    assert context.eval("""
        const element = document.createElement('a');
        element.setAttribute('href', '/search');
        element.hasAttribute('href') && !element.hasAttribute('missing')
            && typeof element.click === 'function'
    """)
    assert "[native code]" in native_now
    assert context.eval("""
        Array.from({length: 20}, () => performance.now()).some(t => t % 1 !== 0)
    """)
    assert context.eval("""
        Math.abs(performance.timeOrigin + performance.now() - Date.now()) < 100
    """)
    assert context.eval("""
        let passiveRead = false;
        addEventListener('test', () => {}, {
            get passive() { passiveRead = true; return false; }
        });
        passiveRead
    """)
    assert context.eval("Object.getPrototypeOf(navigator) === Navigator.prototype")
    assert context.eval("""
        ['plugins', 'mimeTypes', 'webdriver'].every(name => {
            const getter = Object.getOwnPropertyDescriptor(
                Navigator.prototype, name).get;
            try { getter.call(Navigator.prototype); return false; }
            catch (error) { return error instanceof TypeError; }
        })
    """)
    assert context.eval("""
        typeof Permissions.prototype.query === 'function'
            && typeof HTMLMediaElement.prototype.canPlayType === 'function'
            && !('runtime' in chrome)
    """)


def _result():
    return (
        f"SG_SS={_TOKEN}; Path=/; Max-Age=30; Secure",
        "https://www.google.com/search?q=knits&sei=handoff123",
    )


def test_searchguard_document_cookie_excludes_http_only_and_other_hosts():
    session = SyncSession(cache_dir=None)
    url = "https://www.google.com/search?q=knits"
    session.add_cookie("visible=one; Path=/; Secure", url)
    session.add_cookie("hidden=two; Path=/; HttpOnly; Secure", url)
    session.add_cookie("sibling=three; Path=/; Secure", "https://google.com/")

    assert session._document_cookie(url) == "visible=one"
    assert session._document_cookie("http://www.google.com/search") == ""


def test_searchguard_document_cookie_keeps_visible_cookie_shadowed_by_http_only():
    session = SyncSession(cache_dir=None)
    url = "https://www.google.com/search?q=knits"
    session.add_cookie("visible=root; Path=/; Secure", url)
    session.add_cookie("visible=hidden; Path=/search; HttpOnly; Secure", url)

    assert session.get_cookie("visible", url) == "hidden"
    assert session._document_cookie(url) == "visible=root"


def test_sync_inline_solver_scopes_cookie_and_returns_handoff(monkeypatch, tmp_path):
    import wafer._sync as sync_module

    monkeypatch.setattr(sync_module, "solve_searchguard", lambda *_: _result())
    session = SyncSession(cache_dir=str(tmp_path))
    url = "https://www.google.com/search?q=knits"

    result = session._try_inline_solve(ChallengeType.SEARCHGUARD, "shell", url)

    assert result == _result()[1]
    assert session.get_cookie("SG_SS", result) == _TOKEN
    assert session.get_cookie("SG_SS", "https://google.com/search?q=knits") is None
    (cookie,) = [c for c in session._client.cookie_jar.get_all() if c.name == "SG_SS"]
    assert cookie.domain is None
    assert cookie.secure
    assert cookie.path == "/"
    remaining = (
        cookie.expires - datetime.datetime.now(datetime.timezone.utc)
    ).total_seconds()
    assert 0 < remaining <= 30
    assert not list(tmp_path.glob("*.json"))


def test_async_inline_solver_scopes_cookie_and_returns_handoff(monkeypatch, tmp_path):
    import wafer._async as async_module

    monkeypatch.setattr(async_module, "solve_searchguard", lambda *_: _result())
    session = AsyncSession(cache_dir=str(tmp_path))
    url = "https://www.google.com/search?q=knits"

    result = asyncio.run(
        session._try_inline_solve(ChallengeType.SEARCHGUARD, "shell", url)
    )

    assert result == _result()[1]
    assert session.get_cookie("SG_SS", result) == _TOKEN
    assert session.get_cookie("SG_SS", "https://google.com/search?q=knits") is None
    (cookie,) = [c for c in session._client.cookie_jar.get_all() if c.name == "SG_SS"]
    assert cookie.domain is None
    assert cookie.secure
    assert cookie.path == "/"
    remaining = (
        cookie.expires - datetime.datetime.now(datetime.timezone.utc)
    ).total_seconds()
    assert 0 < remaining <= 30
    assert not list(tmp_path.glob("*.json"))


def test_sync_request_replays_searchguard_handoff(monkeypatch):
    import wafer._sync as sync_module

    seen_user_agents = []

    def solve(_body, _url, user_agent, _document_cookie):
        seen_user_agents.append(user_agent)
        return _result()

    monkeypatch.setattr(sync_module, "solve_searchguard", solve)
    monkeypatch.setattr(sync_module.time, "sleep", lambda *_: None)
    shell = (
        '<noscript><meta content="0;url=/httpservice/retry/enablejs"></noscript>'
        '<script>var g="knitsail";</script>'
        '<script>var challenge_version=1;document.cookie="SG_SS=x";</script>'
    )
    session, client = make_sync_session(
        [MockResponse(200, body=shell), MockResponse(200, body="results")],
        use_cookie_jar=True,
        max_retries=0,
        max_rotations=0,
    )

    response = session.get(
        "https://www.google.com/search?q=knits",
        headers={
            "User-Agent": "SearchGuard test UA",
            "Referer": "https://www.google.com/",
            "Sec-Fetch-User": "?1",
        },
    )

    assert response.status_code == 200
    assert response.was_retried
    assert client.request_count == 2
    assert client.request_log[1][1] == _result()[1]
    assert client.request_log[1][2]["headers"]["Referer"] == (
        "https://www.google.com/search?q=knits"
    )
    assert client.request_log[1][2]["headers"]["Sec-Fetch-Site"] == "same-origin"
    assert client.request_log[1][2]["default_headers"] is False
    assert "Sec-Fetch-User" not in client.request_log[1][2]["headers"]
    assert seen_user_agents == ["SearchGuard test UA"]
    assert session.get_cookie("SG_SS", _result()[1]) == _TOKEN


def test_async_request_replays_searchguard_handoff(monkeypatch):
    import wafer._async as async_module

    seen_user_agents = []

    def solve(_body, _url, user_agent, _document_cookie):
        seen_user_agents.append(user_agent)
        return _result()

    monkeypatch.setattr(async_module, "solve_searchguard", solve)
    monkeypatch.setattr(async_module.asyncio, "sleep", lambda *_: _done())
    shell = (
        '<noscript><meta content="0;url=/httpservice/retry/enablejs"></noscript>'
        '<script>var g="knitsail";</script>'
        '<script>var challenge_version=1;document.cookie="SG_SS=x";</script>'
    )
    session, client = make_async_session(
        [MockResponse(200, body=shell), MockResponse(200, body="results")],
        use_cookie_jar=True,
        max_retries=0,
        max_rotations=0,
    )

    response = asyncio.run(
        session.get(
            "https://www.google.com/search?q=knits",
            headers={
                "User-Agent": "SearchGuard test UA",
                "Referer": "https://www.google.com/",
                "Sec-Fetch-User": "?1",
            },
        )
    )

    assert response.status_code == 200
    assert response.was_retried
    assert client.request_count == 2
    assert client.request_log[1][1] == _result()[1]
    assert client.request_log[1][2]["headers"]["Referer"] == (
        "https://www.google.com/search?q=knits"
    )
    assert client.request_log[1][2]["headers"]["Sec-Fetch-Site"] == "same-origin"
    assert client.request_log[1][2]["default_headers"] is False
    assert "Sec-Fetch-User" not in client.request_log[1][2]["headers"]
    assert seen_user_agents == ["SearchGuard test UA"]
    assert session.get_cookie("SG_SS", _result()[1]) == _TOKEN


async def _done():
    return None
