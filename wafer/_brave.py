"""Structural recognition of Brave Search's first-party PoW interstitial."""

import re
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urlparse

BRAVE_ORIGIN = "https://search.brave.com"
BRAVE_COOKIES = (
    "__Secure-token#brave-search-captcha-v2",
    "__Secure-token#brave-search-captcha",
)
BRAVE_STORAGE_KEYS = ("app.blindtoken.tokens.v2", "app.blindtoken.tokens")
_PAGE = re.compile(r'\bpage\s*:\s*["\']/captcha["\']')
_ISSUED = re.compile(r"\bchallengeSet\s*:\s*\{\s*set_token\s*:")


def is_brave_search_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        return (
            parsed.scheme == "https"
            and parsed.hostname == "search.brave.com"
            and parsed.port in (None, 443)
            and parsed.username is None
            and parsed.password is None
            and parsed.path in ("/search", "/captcha")
        )
    except ValueError:
        return False


def brave_url_identity(url: str, *, allow_reload: bool = False) -> tuple:
    """Compare origin/route and parameters, preserving duplicate value order."""
    parsed = urlparse(url)
    query = parse_qsl(parsed.query, keep_blank_values=True)
    if allow_reload and query.count(("_rr", "1")) == 1:
        query.remove(("_rr", "1"))
    values: dict[str, list[str]] = {}
    for key, value in query:
        values.setdefault(key, []).append(value)
    return (
        parsed.scheme,
        parsed.hostname,
        parsed.port or 443,
        parsed.path,
        tuple(sorted((key, tuple(items)) for key, items in values.items())),
    )


class _BraveDocument(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.in_script = False
        self.issued = False
        self.wrapper = False
        self.help = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "script":
            self.in_script = True
        classes = attrs.get("class", "").split()
        if tag == "div" and "captcha-wrapper" in classes:
            self.wrapper = True
        if tag == "a" and attrs.get("href") == "/help/pow-captcha":
            self.help = True

    def handle_endtag(self, tag):
        if tag == "script":
            self.in_script = False

    def handle_data(self, data):
        if self.in_script and all(
            marker in data
            for marker in (
                "__sveltekit_",
                "kit.start(",
                "node_ids:",
                "https://cdn.search.brave.com/serp/",
            )
        ):
            self.issued |= bool(_PAGE.search(data) and _ISSUED.search(data))


def is_brave_challenge(body: str, url: str | None = None) -> bool:
    """Match an issued Svelte gate or its hydrated PoW widget, never prose.

    ``url=None`` is for shared browser passthrough rejection only. Transport
    classification always supplies the exact first-party origin and route.
    Malformed issued work is still a challenge; only Brave's own JS runs it.
    """
    if url is not None and not is_brave_search_url(url):
        return False
    if not body or len(body) > 2_000_000:
        return False
    if "challengeSet" not in body and "captcha-wrapper" not in body:
        return False
    parser = _BraveDocument()
    try:
        parser.feed(body)
    except (ValueError, RecursionError):
        return False
    return parser.issued or (parser.wrapper and parser.help)
