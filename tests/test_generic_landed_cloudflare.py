"""A generic solve that lands on a Cloudflare challenge runs Cloudflare's handler.

``browser_prime`` (and a body the transport could only call ``generic_js``)
asks the browser for a generic solve. The generic wait reports success once
the network goes quiet; on a slow machine that is in the middle of
Cloudflare's JS challenge, so the solve returned with no ``cf_clearance``.
"""

from unittest.mock import MagicMock, patch

from tests import test_browser

URL = "https://www.example.com/"
CLEARANCE = [{"name": "cf_clearance", "value": "x", "domain": ".example.com"}]
CHALLENGE_HEADERS = {"cf-mitigated": "challenge", "content-type": "text/html"}
PAGE_HTML = "<html><body>" + "catalogue content " * 200 + "</body></html>"
CHALLENGED = [(URL, 403, CHALLENGE_HEADERS)]


def _solve(documents, challenge_type="generic_js", dispatch=True):
    """Run ``_solve_on_worker`` with *documents* served as main-frame
    responses; returns (result, dispatched challenge types)."""
    navigation = test_browser.TestBrowserSolverFailClosed._cloudflare_navigation
    solver, context, page, response = navigation(
        response_url=URL, page_url=URL, cookies=CLEARANCE, status=403,
    )
    page.content.return_value = PAGE_HTML
    response.headers = dict(CHALLENGE_HEADERS)

    def goto(*_args, **_kwargs):
        for name, handler in [c.args for c in page.on.call_args_list]:
            if name != "response":
                continue
            for doc_url, status, headers in documents:
                doc = MagicMock()
                doc.url = doc_url
                doc.status = status
                doc.headers = headers
                doc.request.resource_type = "document"
                doc.request.frame = page.main_frame
                handler(doc)
        return response

    page.goto.side_effect = goto
    dispatched = []

    def dispatch_challenge(_page, kind, *_args, **_kwargs):
        dispatched.append(kind)
        return dispatch

    try:
        with (
            patch.object(solver, "_create_context", return_value=context),
            patch.object(solver, "_setup_headless_patches"),
            patch.object(solver, "_dispatch_challenge", side_effect=dispatch_challenge),
        ):
            result = solver._solve_on_worker(URL, challenge_type, timeout=5)
    finally:
        solver.close()
    return result, dispatched


class TestGenericSolveLandedOnCloudflare:
    def test_marked_challenge_document_gets_cloudflare_handler(self):
        _result, dispatched = _solve([(URL, 403, dict(CHALLENGE_HEADERS))])
        assert dispatched == ["cloudflare"]

    def test_marked_challenge_at_429_gets_cloudflare_handler(self):
        _result, dispatched = _solve([(URL, 429, dict(CHALLENGE_HEADERS))])
        assert dispatched == ["cloudflare"]

    def test_unmarked_403_keeps_generic_wait(self):
        # Another WAF's refusal, or an origin's own 403: no Cloudflare marker.
        _result, dispatched = _solve([(URL, 403, {"content-type": "text/html"})])
        assert dispatched == ["generic_js"]

    def test_unreadable_headers_keep_generic_wait(self):
        # No status fallback here: a bare 403 is not Cloudflare's to solve.
        _result, dispatched = _solve([(URL, 403, None)])
        assert dispatched == ["generic_js"]

    def test_page_that_already_cleared_keeps_generic_wait(self):
        _result, dispatched = _solve([
            (URL, 403, dict(CHALLENGE_HEADERS)),
            (URL, 200, {"content-type": "text/html"}),
        ])
        assert dispatched == ["generic_js"]

    def test_navigation_response_counts_when_no_document_was_recorded(self):
        _result, dispatched = _solve([])
        assert dispatched == ["cloudflare"]

    def test_other_requested_types_are_not_rerouted(self):
        _result, dispatched = _solve(
            [(URL, 403, dict(CHALLENGE_HEADERS))], challenge_type="datadome"
        )
        assert dispatched == ["datadome"]

    def test_cloudflare_handler_success_is_a_solve(self):
        result, dispatched = _solve(CHALLENGED, dispatch=True)
        assert dispatched == ["cloudflare"]
        assert result is not None
        assert any(c["name"] == "cf_clearance" for c in result.cookies)

    def test_cloudflare_handler_failure_is_no_solve(self):
        result, dispatched = _solve(CHALLENGED, dispatch=False)
        assert dispatched == ["cloudflare"]
        assert result is None

    def test_challenge_gone_after_all_counts_as_the_generic_success(self):
        # Cloudflare's handler returns None when no challenge is left: the
        # page moved on by itself, which the generic wait reports as solved.
        result, dispatched = _solve(CHALLENGED, dispatch=None)
        assert dispatched == ["cloudflare"]
        assert result is not None
        assert result.challenge_absent is False


class _FakeClock:
    """``time`` for the Cloudflare handler: moves only when it waits."""

    def __init__(self):
        self.now = 1000.0

    def monotonic(self):
        return self.now


class TestRealCloudflareHandler:
    """The rerouted solve runs the real ``wait_for_cloudflare`` here, on a
    page that stays on the challenge and never sets ``cf_clearance``."""

    CHALLENGE_HTML = (
        "<html><head><title>Just a moment...</title></head><body>"
        "<script>window._cf_chl_opt={cType:'non-interactive'};</script>"
        "</body></html>"
    )

    def _solve_unresolved(self, documents):
        navigation = test_browser.TestBrowserSolverFailClosed._cloudflare_navigation
        bookkeeping = [{"name": "__cf_bm", "value": "x", "domain": ".example.com"}]
        solver, context, page, response = navigation(
            response_url=URL, page_url=URL, cookies=bookkeeping, status=403,
        )
        response.headers = dict(CHALLENGE_HEADERS)
        page.context = context
        page.frames = []
        page.title.return_value = "Just a moment..."
        page.content.return_value = self.CHALLENGE_HTML

        def goto(*_args, **_kwargs):
            for name, handler in [c.args for c in page.on.call_args_list]:
                if name != "response":
                    continue
                for doc_url, status, headers in documents:
                    doc = MagicMock()
                    doc.url = doc_url
                    doc.status = status
                    doc.headers = headers
                    doc.request.resource_type = "document"
                    doc.request.frame = page.main_frame
                    handler(doc)
            return response

        page.goto.side_effect = goto
        clock = _FakeClock()

        def browse(_page, _state, seconds):
            clock.now += seconds

        try:
            with (
                patch.object(solver, "_create_context", return_value=context),
                patch.object(solver, "_setup_headless_patches"),
                patch.object(solver, "_start_browse", return_value=None),
                patch.object(solver, "_replay_browse_chunk", side_effect=browse),
                patch("wafer.browser._cloudflare.time", clock),
            ):
                return solver._solve_on_worker(URL, "generic_js", timeout=5)
        finally:
            solver.close()

    def test_unresolved_challenge_is_no_solve(self):
        assert self._solve_unresolved(CHALLENGED) is None

    def test_unresolved_challenge_seen_only_by_goto_is_no_solve(self):
        # No document response was recorded: the navigation's own response
        # must reach the handler too, or after 3s it reads "no challenge here"
        # and the solve returns Cloudflare's bookkeeping cookie as a success.
        assert self._solve_unresolved([]) is None
