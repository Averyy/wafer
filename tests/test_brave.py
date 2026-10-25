"""Brave's real captured gate, bounded browser protocol and session dispatch."""

import html
import re
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from tests.conftest import MockResponse, make_async_session, make_sync_session
from wafer._brave import BRAVE_ORIGIN, is_brave_challenge
from wafer._challenge import ChallengeType, detect_challenge
from wafer._errors import ChallengeDetected, ResponseTooLarge
from wafer.browser._brave import (
    brave_storage_state,
    capture_brave_response,
    finish_brave,
    prepare_brave,
    wait_for_brave,
)
from wafer.browser._solver import _is_passthrough_challenge_html

FIXTURES = Path(__file__).parent / "fixtures"
GATE = (FIXTURES / "brave_captcha_429.html").read_text()
PAGE1 = (FIXTURES / "brave_page1.html").read_bytes()
PAGE2 = (FIXTURES / "brave_page2.html").read_bytes()
URL = BRAVE_ORIGIN + "/search?q=Python+asyncio+documentation&source=web&offset=1"
HEADERS = {"content-type": "text/html"}


def test_real_gate_and_hydrated_gate():
    assert len(GATE) > 50_000
    assert detect_challenge(429, HEADERS, GATE, url=URL) is ChallengeType.BRAVE
    hydrated = (
        '<div class="captcha-wrapper svelte-abc" data-state="verifying"></div>'
        '<a href="/help/pow-captcha">Why?</a>'
    )
    assert detect_challenge(200, HEADERS, hydrated, url=URL) is ChallengeType.BRAVE
    assert _is_passthrough_challenge_html(GATE)
    assert _is_passthrough_challenge_html(hydrated)


@pytest.mark.parametrize(
    "body",
    [
        PAGE1.decode(),
        PAGE2.decode(),
        "Too many requests",
        "CAPTCHA challengeSet access denied",
        html.escape(GATE),
        GATE.replace("<script", "<pre").replace("</script", "</pre"),
        '<div class="captcha-wrapper" data-state="idle"></div>',
        GATE.replace('page:"/captcha"', 'page:"/search"'),
        GATE + " " * 2_000_000,
    ],
)
def test_negative_documents(body):
    assert not is_brave_challenge(body, URL)


@pytest.mark.parametrize(
    "url",
    [
        "http://search.brave.com/search",
        "https://search.brave.com.evil.test/search",
        "https://search.brave.com@evil.test/search",
        "https://search.brave.com:444/search",
        "https://search.brave.com/help/pow-captcha",
        "https://brave.com/search",
    ],
)
def test_origin_scope(url):
    assert not is_brave_challenge(GATE, url)


def test_malformed_work_is_still_identified():
    assert is_brave_challenge(GATE.replace("zero_count:1", "zero_count:-1"), URL)
    assert is_brave_challenge(
        GATE.replace("hash_function_params:{", "bad_params:{"), URL
    )


@pytest.mark.parametrize("rotations", [0, 2])
def test_no_browser_identified_without_rotation(rotations):
    session, client = make_sync_session(
        [MockResponse(429, body=GATE, headers=HEADERS)],
        max_rotations=rotations,
        max_retries=0,
        rate_limit=0,
    )
    if rotations == 0:
        response = session.get(URL)
        assert response.challenge_type == "brave"
        assert response.status_code == 429
    else:
        with pytest.raises(ChallengeDetected, match="brave"):
            session.get(URL)
    assert client.request_count == 1


async def test_async_no_browser_identified():
    session, client = make_async_session(
        [MockResponse(429, body=GATE, headers=HEADERS)],
        max_rotations=0,
        max_retries=0,
        rate_limit=0,
    )
    response = await session.get(URL)
    assert response.challenge_type == "brave"
    assert client.request_count == 1


@pytest.mark.parametrize("async_mode", [False, True])
async def test_failed_browser_never_rotates_or_retries(async_mode):
    solver = MagicMock()
    solver.solve.return_value = None
    # Force the synchronous solver fallback in AsyncSession, also exercising
    # limiter/state transport across that worker boundary.
    solver.asolve = None
    factory = make_async_session if async_mode else make_sync_session
    session, client = factory(
        [MockResponse(429, body=GATE, headers=HEADERS)],
        browser_solver=solver,
        max_rotations=3,
        max_retries=0,
        rate_limit=0,
    )
    with pytest.raises(ChallengeDetected, match="brave"):
        if async_mode:
            await session.get(URL)
        else:
            session.get(URL)
    assert client.request_count == 1
    assert solver.solve.call_count == 1
    config = solver.solve.call_args.kwargs["replay"]["_brave"]
    assert config["state"] is session._brave_state


def response(body=PAGE2, status=200, url=URL):
    result = MagicMock()
    result.url = url
    result.status = status
    result.body.return_value = body
    result.all_headers.return_value = HEADERS
    result.headers_array.return_value = []
    return result


def test_network_capture_exact_bytes():
    captured = capture_brave_response(response(), SimpleNamespace(url=URL), URL, None)
    assert captured.body == PAGE2
    assert captured.url == URL
    with pytest.raises(ResponseTooLarge):
        capture_brave_response(response(), SimpleNamespace(url=URL), URL, 1000)


@pytest.mark.parametrize(
    "status,body,url,page_url",
    [
        (429, GATE.encode(), URL, URL),
        (200, GATE.encode(), URL, URL),
        (200, PAGE2, URL.replace("offset=1", "offset=0"), URL),
        (200, PAGE2, URL, URL.replace("asyncio", "wrong")),
        (200, PAGE2, "https://example.com/search", URL),
        (200, b"<html>quiet page</html>", URL, URL),
    ],
)
def test_capture_rejects_gate_and_wrong_document(status, body, url, page_url):
    assert (
        capture_brave_response(
            response(body, status, url), SimpleNamespace(url=page_url), URL, None
        )
        is None
    )


def browser_page(states, gate=GATE):
    page = MagicMock()
    page.url = URL
    page.content.return_value = gate
    wrapper = MagicMock()
    wrapper.count.return_value = 1
    wrapper.first.get_attribute.side_effect = states
    button = MagicMock()
    button.count.return_value = 1
    button.first.is_enabled.return_value = True
    page.locator.side_effect = lambda selector: (
        wrapper if selector == ".captcha-wrapper[data-state]" else button
    )
    solver = SimpleNamespace(_bounded_page_content=lambda *args: gate)
    return page, solver, button


def test_manual_large_set_clicked_once_and_error_stops():
    page, solver, button = browser_page(["idle", "idle", "verifying", "error"])
    with patch("wafer.browser._brave.idle"):
        assert wait_for_brave(
            solver,
            page,
            URL,
            [],
            time.monotonic() + 2,
            None,
            {"accepted": False, "rejected": False},
        ) == (None, False)
    button.first.click.assert_called_once()


def test_small_set_never_clicked_even_while_idle():
    small = re.sub(r"tokens:\[[^\]]*\]", 'tokens:["issued-token"]', GATE, count=1)
    page, solver, button = browser_page(["idle", "verifying", "error"], small)
    with patch("wafer.browser._brave.idle"):
        assert wait_for_brave(
            solver,
            page,
            URL,
            [],
            time.monotonic() + 2,
            None,
            {"accepted": False, "rejected": False},
        ) == (None, False)
    button.first.click.assert_not_called()


def test_rejection_and_timeout_never_clicked():
    for evidence, deadline in [
        ({"accepted": False, "rejected": True}, time.monotonic() + 1),
        ({"accepted": False, "rejected": False}, time.monotonic() - 1),
    ]:
        page, solver, button = browser_page([])
        assert wait_for_brave(solver, page, URL, [], deadline, None, evidence) == (
            None,
            False,
        )
        button.first.click.assert_not_called()


def test_detached_context_then_real_network_document():
    page, solver, _ = browser_page([])
    solver._bounded_page_content = MagicMock(side_effect=RuntimeError("detached"))
    documents = []
    with patch(
        "wafer.browser._brave.idle",
        side_effect=lambda _: documents.append((URL, 200, response())),
    ):
        captured, cleared = wait_for_brave(
            solver,
            page,
            URL,
            documents,
            time.monotonic() + 1,
            None,
            {"accepted": False, "rejected": False},
        )
    assert captured.body == PAGE2
    assert not cleared


def test_challenge_free_navigation_is_passthrough_without_clearance():
    page, solver, button = browser_page([])
    solver._browser_ua = "Chrome"
    solver._browser_version = "154.0.0.0"
    context = MagicMock()
    context.cookies.return_value = []
    context.storage_state.return_value = {"origins": []}
    result = finish_brave(
        solver,
        context,
        page,
        URL,
        [(URL, 200, response())],
        time.monotonic() + 1,
        None,
        ({}, {"accepted": False, "rejected": False}),
    )
    assert result.response.body == PAGE2
    assert result.challenge_absent
    button.first.click.assert_not_called()


def test_prepare_state_scope_pacing_and_rejected_state_eviction():
    context, page, limiter = MagicMock(), MagicMock(), MagicMock()
    limiter._delay_for.return_value = 0
    state = {"storage": [{"name": "app.blindtoken.tokens.v2", "value": "[]"}]}
    replay = {"_brave": {"state": state, "limiter": limiter}}
    restored = brave_storage_state(replay)
    assert restored["origins"] == [
        {
            "origin": BRAVE_ORIGIN,
            "localStorage": state["storage"],
        }
    ]
    prepared, evidence = prepare_brave(
        context,
        page,
        URL,
        {"_brave": {"state": state, "limiter": limiter}},
        time.monotonic() + 10,
    )
    assert prepared is state and state == {}
    context.add_init_script.assert_not_called()
    callback = context.route.call_args.args[1]
    route = MagicMock()
    route.request.url = URL
    route.request.is_navigation_request.return_value = True
    route.request.frame = page.main_frame
    callback(route)
    limiter.wait_sync.assert_not_called()
    limiter.record.assert_called_once_with("search.brave.com")
    route.continue_.assert_called_once()
    route.request.url = "https://evil.example/search"
    callback(route)
    route.abort.assert_called_once()
    assert evidence == {"accepted": False, "rejected": True}


def test_deadline_aborts_exchange_and_duplicate_pow_is_stopped():
    for expired in (False, True):
        context, page = MagicMock(), MagicMock()
        _, evidence = prepare_brave(
            context, page, URL, {}, time.monotonic() + (-1 if expired else 10)
        )
        route = MagicMock()
        route.request.url = BRAVE_ORIGIN + "/api/captcha/pow?brave=0"
        route.request.is_navigation_request.return_value = False
        callback = context.route.call_args.args[1]
        callback(route)
        page._wafer_brave_flush()
        if expired:
            route.continue_.assert_not_called()
        else:
            callback(route)
            assert evidence["rejected"]
            route.continue_.assert_called_once()
        route.abort.assert_called_once()


def test_accepted_pow_reload_allows_only_traced_rr_and_original_query():
    reload_url = URL + "&_rr=1"
    page = SimpleNamespace(url=URL)
    assert capture_brave_response(response(url=reload_url), page, URL, None) is None
    captured = capture_brave_response(
        response(url=reload_url), page, URL, None, allow_pow_reload=True
    )
    assert captured.body == PAGE2
    for wrong in (URL + "&_rr=2", reload_url.replace("offset=1", "offset=0")):
        assert (
            capture_brave_response(
                response(url=wrong), page, URL, None, allow_pow_reload=True
            )
            is None
        )


def test_validated_origin_storage_retained_without_other_localstorage():
    page, solver, _ = browser_page([])
    solver._browser_ua = "Chrome"
    solver._browser_version = "155.0.0.0"
    context = MagicMock()
    context.cookies.return_value = []
    tokens = {"name": "app.blindtoken.tokens.v2", "value": "[]"}
    context.storage_state.return_value = {
        "origins": [
            {
                "origin": BRAVE_ORIGIN,
                "localStorage": [
                    tokens,
                    {"name": "unrelated", "value": "private"},
                ],
            },
            {"origin": "https://example.com", "localStorage": [tokens]},
        ]
    }
    state = {}
    result = finish_brave(
        solver,
        context,
        page,
        URL,
        [(URL, 200, response())],
        time.monotonic() + 1,
        None,
        (state, {"accepted": False, "rejected": False}),
    )
    assert result.response.body == PAGE2
    assert state == {"storage": [tokens]}


def test_ordinary_429_still_uses_rate_limit_path():
    session, client = make_sync_session(
        [MockResponse(429, headers={"retry-after": "1"}, body="Too many requests")],
        max_rotations=0,
        max_retries=0,
    )
    result = session.get(URL)
    assert result.status_code == 429
    assert result.challenge_type is None
    assert client.request_count == 1


def test_real_jar_and_cache_roundtrip_for_validated_brave_cookie(tmp_path):
    from wafer import SyncSession
    from wafer._brave import BRAVE_COOKIES
    from wafer.browser import CapturedResponse, SolveResult

    cookie_name = BRAVE_COOKIES[0]
    solver = MagicMock()
    solver.proxy_server = None
    solver.browser_identity = None
    solver.solve.return_value = SolveResult(
        cookies=[
            {
                "name": cookie_name,
                "value": "validated-test-token",
                "domain": "search.brave.com",
                "path": "/",
                "secure": True,
                "sameSite": "Strict",
                "expires": time.time() + 1800,
            }
        ],
        user_agent=(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36"
        ),
        browser_version="155.0.8059.85",
        response=CapturedResponse(URL, 200, HEADERS, PAGE2),
    )
    # This tests the actual wreq jar and disk cache, not server acceptance of
    # the cookie. Only a live search carrying real clearance can prove that.
    with SyncSession(browser_solver=solver, cache_dir=str(tmp_path)) as session:
        result = session._try_browser_solve(
            ChallengeType.BRAVE, URL, time.monotonic() + 5
        )
        assert result.content == PAGE2
        assert session.get_cookie(cookie_name, URL) == "validated-test-token"
    with SyncSession(cache_dir=str(tmp_path)) as restarted:
        assert restarted.get_cookie(cookie_name, URL) == "validated-test-token"
        assert restarted.get_cookie(cookie_name, "https://brave.com/") is None
        assert restarted._brave_state == {}


def test_navigation_size_guard_applies_during_solve():
    page, solver, button = browser_page([])
    with pytest.raises(ResponseTooLarge):
        wait_for_brave(
            solver,
            page,
            URL,
            [],
            time.monotonic() + 1,
            1000,
            {"accepted": False, "rejected": False},
            {"exceeded": True, "size": 1001},
        )
    button.first.click.assert_not_called()


def test_non_pow_widget_stops_without_click():
    page, solver, button = browser_page([])
    page.locator.side_effect = lambda selector: SimpleNamespace(
        count=lambda: 0 if selector == ".captcha-wrapper[data-state]" else 1
    )
    assert wait_for_brave(
        solver,
        page,
        URL,
        [],
        time.monotonic() + 1,
        None,
        {"accepted": False, "rejected": False},
    ) == (None, False)
    button.first.click.assert_not_called()


def test_solver_completes_manual_pow_and_returns_exact_reload_response():
    from wafer._brave import BRAVE_COOKIES
    from wafer.browser import BrowserSolver

    solver = BrowserSolver(solve_timeout=2)
    solver._browser = MagicMock()
    solver._browser.is_connected.return_value = True
    solver._browser_ua = "Chrome/155.0.0.0"
    solver._browser_version = "155.0.8059.85"
    solver._needs_screenxy_patch = False
    page, _, button = browser_page(["idle", "idle"])
    context = MagicMock()
    context.new_page.return_value = page
    context.cookies.return_value = [
        {
            "name": BRAVE_COOKIES[0],
            "value": "validated-test-cookie",
            "domain": "search.brave.com",
            "path": "/",
            "secure": True,
        }
    ]
    context.storage_state.return_value = {"origins": []}
    listeners = []
    page.on.side_effect = lambda event, callback: (
        listeners.append(callback) if event == "response" else None
    )

    def emit(document):
        document.request.frame = page.main_frame
        for callback in listeners:
            callback(document)
        return document

    initial = response(GATE.encode(), status=429)
    initial.request.resource_type = "document"
    page.goto.side_effect = lambda *args, **kwargs: emit(initial)
    completed = response(url=URL + "&_rr=1")
    completed.request.resource_type = "document"
    pow_response = response(status=200, url=BRAVE_ORIGIN + "/api/captcha/pow?brave=0")
    pow_response.request.resource_type = "fetch"
    button.first.click.side_effect = lambda **kwargs: (
        emit(pow_response),
        emit(completed),
    )
    state = {}
    try:
        with (
            patch.object(solver, "_create_context", return_value=context),
            patch.object(solver, "_setup_headless_patches"),
            patch.object(solver, "_verify_headless_patches"),
            patch.object(solver, "_bounded_page_content", return_value=GATE),
            patch("wafer.browser._brave.idle"),
        ):
            result = solver._solve_on_worker(
                URL,
                "brave",
                timeout=2,
                replay={"method": "GET", "_brave": {"state": state}},
            )
    finally:
        solver.close()
    assert result.response.body == PAGE2
    assert result.response.url == URL + "&_rr=1"
    assert not result.challenge_absent
    assert state == {"storage": []}
    button.first.click.assert_called_once()
    context.close.assert_called_once()


@pytest.mark.parametrize("async_mode", [False, True])
@pytest.mark.parametrize(
    "body,returned_url",
    [
        (GATE.encode(), URL),
        (PAGE2, URL.replace("offset=1", "offset=0")),
    ],
)
async def test_session_rejects_bad_custom_passthrough_before_state_import(
    async_mode, body, returned_url
):
    from wafer._brave import BRAVE_COOKIES
    from wafer.browser import CapturedResponse, SolveResult

    solver = MagicMock()
    solver.asolve = None
    solver.solve.return_value = SolveResult(
        cookies=[
            {
                "name": BRAVE_COOKIES[0],
                "value": "rejected-test-cookie",
                "domain": "search.brave.com",
                "path": "/",
                "secure": True,
            }
        ],
        user_agent="Chrome/155.0.0.0",
        response=CapturedResponse(returned_url, 200, HEADERS, body),
    )
    factory = make_async_session if async_mode else make_sync_session
    session, client = factory(
        [MockResponse(429, headers=HEADERS, body=GATE)],
        browser_solver=solver,
        max_rotations=0,
        max_retries=0,
        use_cookie_jar=True,
    )
    session._rebuild_client = MagicMock()
    response_value = await session.get(URL) if async_mode else session.get(URL)
    assert response_value.status_code == 429
    assert response_value.challenge_type == "brave"
    assert client.request_count == 1
    assert session.get_cookie(BRAVE_COOKIES[0], URL) is None
    session._rebuild_client.assert_not_called()


def test_navigation_query_change_is_stopped_before_network():
    context, page = MagicMock(), MagicMock()
    _, evidence = prepare_brave(context, page, URL, {}, time.monotonic() + 1)
    route = MagicMock()
    route.request.url = URL.replace("offset=1", "offset=2")
    route.request.is_navigation_request.return_value = True
    route.request.frame = page.main_frame
    context.route.call_args.args[1](route)
    route.abort.assert_called_once()
    route.continue_.assert_not_called()
    assert evidence["rejected"]


def test_query_identity_keeps_duplicate_value_order():
    from wafer._brave import brave_url_identity

    assert brave_url_identity(URL + "&q=other") != brave_url_identity(
        URL.replace("q=Python+asyncio+documentation", "q=other")
        + "&q=Python+asyncio+documentation"
    )
    assert (
        capture_brave_response(
            response(url=URL + "&_rr=1&_rr=1"),
            SimpleNamespace(url=URL),
            URL,
            None,
            allow_pow_reload=True,
        )
        is None
    )


def test_queued_browser_exchanges_keep_pump_free_and_share_actual_limiter():
    from wafer._ratelimit import RateLimiter

    context, page = MagicMock(), MagicMock()
    limiter = RateLimiter(min_interval=6, jitter=0)
    with (
        patch("wafer.browser._brave.time.monotonic", return_value=10) as clock,
        patch("wafer.browser._brave.idle") as pump,
    ):
        prepare_brave(
            context, page, URL, {"_brave": {"limiter": limiter}}, deadline=100
        )
        callback = context.route.call_args.args[1]
        navigation = MagicMock()
        navigation.request.url = URL
        navigation.request.is_navigation_request.return_value = True
        navigation.request.frame = page.main_frame
        callback(navigation)
        routes = [MagicMock(), MagicMock()]
        for route in routes:
            route.request.url = BRAVE_ORIGIN + "/api/tokens/keys"
            route.request.is_navigation_request.return_value = False
            callback(route)
            route.continue_.assert_not_called()
        pump.assert_not_called()  # callbacks queue instead of sleeping
        page._wafer_brave_flush()
        routes[0].continue_.assert_not_called()
        clock.return_value = 16.01
        page._wafer_brave_flush()
        routes[0].continue_.assert_called_once()
        routes[1].continue_.assert_not_called()
        clock.return_value = 22.02
        page._wafer_brave_flush()
        routes[1].continue_.assert_called_once()
        assert limiter._last_request["search.brave.com"] == 22.02


def test_cancel_drains_pending_routes_and_prevents_new_traffic():
    context, page = MagicMock(), MagicMock()
    prepare_brave(context, page, URL, {}, time.monotonic() + 10)
    callback = context.route.call_args.args[1]
    pending = MagicMock()
    pending.request.url = BRAVE_ORIGIN + "/api/tokens/keys"
    pending.request.is_navigation_request.return_value = False
    callback(pending)
    pending.continue_.assert_not_called()
    page._wafer_brave_cancel()
    pending.abort.assert_called_once()
    context.unroute_all.assert_called_once_with(behavior="ignoreErrors")
    later = MagicMock()
    callback(later)
    later.abort.assert_called_once()
    later.continue_.assert_not_called()
