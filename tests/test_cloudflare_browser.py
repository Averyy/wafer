"""The Cloudflare browser handler's success conditions across challenge stages.

stackoverflow.com (2026-11-03): a non-interactive first stage sets cf_clearance,
then Cloudflare can answer the form POST carrying it with a second challenge
(429 with Turnstile, sometimes a 403 after that) before the real page.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from wafer._challenge import ChallengeType, detect_challenge
from wafer.browser import _cloudflare
from wafer.browser._cloudflare import cleared_in_passing, wait_for_cloudflare

_URL = "https://stackoverflow.com/questions/1"
_CHALLENGE_HTML = (
    "<html><head><title>Just a moment...</title></head><body>"
    "<script>window._cf_chl_opt={cType: 'managed'};</script>"
    "<script src='/cdn-cgi/challenge-platform/h/g/orchestrate/chl_page/v1'>"
    "</script></body></html>"
)


def _doc(status, mitigated):
    headers = {"cf-mitigated": "challenge"} if mitigated else {"server": "cloudflare"}
    return (_URL, status, SimpleNamespace(headers=headers))


class _Clock:
    """A monotonic clock that advances a little on every read."""

    def __init__(self, step=0.25):
        self.now = 0.0
        self.step = step

    def monotonic(self):
        self.now += self.step
        return self.now


def _page(cookies_fn):
    page = MagicMock()
    page.context.cookies.side_effect = cookies_fn
    page.frames = []
    page.title.return_value = "Just a moment..."
    page.content.return_value = _CHALLENGE_HTML
    return page


def _run(page, documents, timeout_ms=60_000, on_tick=None):
    solver = MagicMock()
    clock = _Clock()
    fake_time = SimpleNamespace(monotonic=clock.monotonic)
    if on_tick is not None:
        solver._replay_browse_chunk.side_effect = lambda *a, **k: on_tick(clock.now)
    with patch.object(_cloudflare, "time", fake_time):
        return wait_for_cloudflare(solver, page, timeout_ms, documents=documents)


class TestStagedClearance:
    def test_first_stage_clearance_under_a_new_challenge_is_not_solved(self):
        # cf_clearance from stage 1 is in the jar while the 429 stage-2
        # challenge is up; the real page only arrives later.
        documents = [_doc(403, True), _doc(429, True)]
        clearance = [{"name": "cf_clearance", "value": "stage1"}]
        page = _page(lambda: clearance)

        def tick(now):
            if now > 5 and len(documents) == 2:
                documents.append(_doc(200, False))

        assert _run(page, documents, on_tick=tick) is True
        assert len(documents) == 3

    def test_clearance_with_no_documents_keeps_the_old_signal(self):
        page = _page(lambda: [{"name": "cf_clearance", "value": "x"}])
        solver = MagicMock()
        assert wait_for_cloudflare(solver, page, 5_000) is True

    def test_clearance_on_a_non_challenge_document_is_solved(self):
        page = _page(lambda: [{"name": "cf_clearance", "value": "x"}])
        assert _run(page, [_doc(403, True), _doc(200, False)]) is True

    def test_challenge_title_on_a_challenge_document_is_not_content(self):
        # A stage-2 page whose title is not "Just a moment" is still a
        # challenge while its document is one.
        page = _page(lambda: [{"name": "cf_clearance", "value": "x"}])
        page.title.return_value = "Too many requests"
        assert _run(page, [_doc(403, True), _doc(429, True)], timeout_ms=3_000) is False


class TestRedirectToAnotherOrigin:
    def test_a_challenge_on_another_origin_is_not_a_next_stage(self):
        # www.glassdoor.com 301s to www.glassdoor.ca and Cloudflare challenges
        # both. Solving .ca's challenge here took ~19s, then the session threw
        # it away (another origin) and solved .ca again on the replay.
        documents = [
            ("https://www.glassdoor.com/", 403, SimpleNamespace(
                headers={"cf-mitigated": "challenge"})),
            ("https://www.glassdoor.ca/index.htm", 403, SimpleNamespace(
                headers={"cf-mitigated": "challenge"})),
        ]
        page = _page(lambda: [{"name": "cf_clearance", "value": "com"}])
        assert _run(page, documents, timeout_ms=3_000) is True

    def test_the_same_origin_on_another_path_is_still_a_next_stage(self):
        documents = [
            ("https://stackoverflow.com/questions/1", 403, SimpleNamespace(
                headers={"cf-mitigated": "challenge"})),
            ("https://stackoverflow.com/questions/1?x", 429, SimpleNamespace(
                headers={"cf-mitigated": "challenge"})),
        ]
        page = _page(lambda: [{"name": "cf_clearance", "value": "stage1"}])
        assert _run(page, documents, timeout_ms=3_000) is False


class TestPassThroughGrace:
    def test_no_iframe_on_a_challenge_document_is_not_a_pass_through(self):
        # In the emulated Linux image the non-interactive first stage
        # outlasted the 3s grace; returning None there ended a solve that
        # was still running.
        documents = [_doc(403, True)]
        page = _page(lambda: [])

        def tick(now):
            if now > 6 and len(documents) == 1:
                documents.append(_doc(200, False))

        cookies = []
        page.context.cookies.side_effect = lambda: cookies

        def tick_with_clearance(now):
            tick(now)
            if len(documents) == 2:
                cookies.append({"name": "cf_clearance", "value": "x"})

        assert _run(page, documents, on_tick=tick_with_clearance) is True

    def test_no_iframe_and_no_challenge_document_is_a_pass_through(self):
        page = _page(lambda: [])
        assert _run(page, [_doc(200, False)]) is None

    def test_a_challenge_that_never_moves_gives_up(self):
        page = _page(lambda: [])
        with patch.object(_cloudflare, "_STALLED_CHALLENGE_SECONDS", 5.0):
            assert _run(page, [_doc(403, True)]) is False


class TestClearedInPassing:
    def test_a_marked_challenge_then_a_page(self):
        assert cleared_in_passing([_doc(403, True), _doc(200, False)])

    def test_an_unmarked_403_earned_nothing(self):
        assert not cleared_in_passing([_doc(403, False), _doc(200, False)])

    def test_still_on_a_challenge(self):
        assert not cleared_in_passing([_doc(403, True), _doc(429, True)])

    def test_one_document(self):
        assert not cleared_in_passing([_doc(200, False)])
        assert not cleared_in_passing([])


class TestEscalatedStageBody:
    def test_429_with_challenge_markers_is_cloudflare(self):
        # A render classifies its DOM without the real headers; the 429 stage
        # read as generic_js and never got the Turnstile handler.
        assert (
            detect_challenge(429, {"content-type": "text/html"}, _CHALLENGE_HTML)
            == ChallengeType.CLOUDFLARE
        )
