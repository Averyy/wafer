"""The Akamai browser handler's success conditions."""

import json
from unittest.mock import MagicMock

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
