"""The Akamai browser handler's success conditions."""

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from wafer.browser import _akamai
from wafer.browser._akamai import _challenge_then_document, wait_for_akamai

_STUB = '<html><body><div id="sec-if-cpt"></div>behavioral-content</body></html>'
_REAL = "<html><body>" + "dog treats " * 2000 + "</body></html>"


def _page(documents_html, cookies=()):
    """A page whose document reads return *documents_html* in turn (last repeats)."""
    page = MagicMock()
    reads = list(documents_html)

    def evaluate(expression):
        html = reads.pop(0) if len(reads) > 1 else reads[0]
        return json.dumps([len(html), html[:10000]])

    page.evaluate.side_effect = evaluate
    page.context.cookies.return_value = list(cookies)
    return page


def _solver():
    solver = MagicMock()
    solver._start_browse.return_value = object()
    return solver


class TestChallengeThenDocument:
    def test_challenge_followed_by_a_2xx(self):
        assert _challenge_then_document(
            [("u", 429), ("u", 301), ("v", 301), ("w", 200)]
        )

    def test_no_challenge_document(self):
        assert not _challenge_then_document([("u", 200)])

    def test_still_on_the_challenge(self):
        assert not _challenge_then_document([("u", 200), ("u", 429)])

    def test_challenge_then_another_block(self):
        assert not _challenge_then_document([("u", 429), ("u", 403)])

    def test_nothing_recorded(self):
        assert not _challenge_then_document(None)
        assert not _challenge_then_document([])


class TestWaitForAkamai:
    def test_stub_gone_before_the_first_look_still_resolves(self):
        # chewy.com: the 429 behavioral page reloads and redirects to a 200
        # page before the handler looks, and no _abck is ever set. It waited
        # out its whole budget (2026-10-06).
        page = _page([_REAL])
        documents = [("p", 429), ("p", 301), ("q", 301), ("c", 200)]
        assert wait_for_akamai(_solver(), page, 5_000, documents=documents)

    def test_real_content_alone_is_not_taken_for_cleared(self):
        # A protected page loads the sensor and real content before _abck is
        # valid; with no challenge document seen, keep waiting for _abck.
        page = _page([_REAL])
        assert not wait_for_akamai(_solver(), page, 50, documents=[("p", 200)])

    def test_a_stub_that_grows_into_content(self):
        page = _page([_STUB, _STUB, _REAL])
        assert wait_for_akamai(_solver(), page, 5_000)

    def test_an_abck_change(self):
        page = _page([_REAL])
        page.context.cookies.side_effect = [
            [{"name": "_abck", "value": "old"}],
            [{"name": "_abck", "value": "new"}],
        ]
        assert wait_for_akamai(_solver(), page, 5_000)

    def test_behavioral_abck_change_without_navigation_is_not_solved(self):
        # The sensor always updates _abck, even when the server rejects
        # the fingerprint and never lets the browser through. A behavioral
        # challenge is only solved when the page navigates to real content.
        page = _page([_STUB])
        first = True

        def cookies():
            nonlocal first
            if first:
                first = False
                return [{"name": "_abck", "value": "old"}]
            return [{"name": "_abck", "value": "new"}]

        page.context.cookies.side_effect = cookies
        assert not wait_for_akamai(_solver(), page, 100)

    def test_behavioral_abck_change_with_navigation_is_solved(self):
        # The sensor updates _abck AND the page navigates to real content.
        page = _page([_STUB, _STUB, _REAL])
        first = True

        def cookies():
            nonlocal first
            if first:
                first = False
                return [{"name": "_abck", "value": "old"}]
            return [{"name": "_abck", "value": "new"}]

        page.context.cookies.side_effect = cookies
        assert wait_for_akamai(_solver(), page, 5_000)

    def test_reads_never_go_through_page_content(self):
        # page.content() is a Playwright evaluation sent as a user gesture,
        # which marks the page user-activated.
        page = _page([_REAL])
        wait_for_akamai(_solver(), page, 5_000, documents=[("p", 429), ("c", 200)])
        page.content.assert_not_called()


# Akamai's refusal document: www.ebay.ca's 403 "Error Page" to a cold Linux
# Chrome (stock Chrome for Testing included), loading Akamai's script at
# /<random path>?v=<uuid> (2026-11-03). After the script posted, one reload
# went through eBay's splash challenge to the results page.
_REFUSAL = (
    Path(__file__).parent / "fixtures" / "ebay_akamai_refusal_2026-11-03.html"
).read_text()
_SPLASH = (
    Path(__file__).parent / "fixtures" / "ebay_splash_challenge_2026-11-03.html"
).read_text()


class _Clock:
    def __init__(self, step=0.25):
        self.now = 0.0
        self.step = step

    def monotonic(self):
        self.now += self.step
        return self.now


def _run_refusal(page, documents, timeout_ms=120_000):
    clock = _Clock()
    with patch.object(_akamai, "time", SimpleNamespace(monotonic=clock.monotonic)):
        return wait_for_akamai(_solver(), page, timeout_ms, documents=documents)


class TestRefusalDocument:
    def test_retried_once_then_lands_on_content(self):
        documents = [("u", 403)]
        page = _page([_REFUSAL])
        pages = {"html": _REFUSAL}
        page.evaluate.side_effect = lambda expression: json.dumps(
            [len(pages["html"]), pages["html"][:10000]]
        )

        def reload(**kwargs):
            documents.extend([("u", 307), ("s", 200)])
            pages["html"] = _SPLASH

            def land():
                documents.append(("u", 200))
                pages["html"] = _REAL

            page.reload.land = land

        page.reload.side_effect = reload
        calls = {"n": 0}

        def cookies():
            calls["n"] += 1
            if calls["n"] == 3 and hasattr(page.reload, "land"):
                page.reload.land()
            return []

        page.context.cookies.side_effect = cookies
        assert _run_refusal(page, documents) is True
        assert page.reload.call_count == 1

    def test_splash_is_not_taken_for_content(self):
        # eBay's splash challenge is 13KB with no sec-if-cpt marker.
        documents = [("u", 403)]
        page = _page([_REFUSAL])

        def reload(**kwargs):
            documents.extend([("u", 307), ("s", 200)])
            page.evaluate.side_effect = lambda expression: json.dumps(
                [len(_SPLASH), _SPLASH[:10000]]
            )

        page.reload.side_effect = reload
        assert _run_refusal(page, documents, timeout_ms=30_000) is False

    def test_a_refusal_that_survives_the_retry_ends_quickly(self):
        # homedepot.com's refusal polled the whole 142s budget.
        documents = [("u", 403)]
        page = _page([_REFUSAL])
        page.reload.side_effect = lambda **kwargs: documents.append(("u", 403))
        clock = _Clock()
        with patch.object(
            _akamai, "time", SimpleNamespace(monotonic=clock.monotonic)
        ):
            assert not wait_for_akamai(
                _solver(), page, 142_000, documents=documents
            )
        assert page.reload.call_count == 1
        assert clock.now < (
            _akamai._DENY_SENSOR_WAIT + _akamai._DENY_RETRY_GRACE + 5
        )

    def test_an_abck_change_on_the_refusal_is_not_clearance(self):
        documents = [("u", 403)]
        page = _page([_REFUSAL])
        page.reload.side_effect = lambda **kwargs: documents.append(("u", 403))
        values = iter(["a", "b", "c", "d", "e", "f"] + ["g"] * 10_000)
        page.context.cookies.side_effect = lambda: [
            {"name": "_abck", "value": next(values)}
        ]
        assert not _run_refusal(page, documents)

    def test_the_behavioral_stub_is_not_a_refusal(self):
        page = _page([_STUB, _STUB, _REAL])
        assert wait_for_akamai(_solver(), page, 5_000, documents=[("u", 403)])
        page.reload.assert_not_called()
