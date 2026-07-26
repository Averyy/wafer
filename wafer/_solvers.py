"""Inline challenge solvers -- pure Python, no browser needed.

ACW: Alibaba Cloud WAF -- shuffle + XOR (~1ms)
Amazon: Rate-limit captcha -- form parsing + submission (~100ms)
TMD: Alibaba TMD -- session warming via homepage fetch
Reddit: Logged-out verification form parsing + solution derivation
"""

import logging
import re
from dataclasses import dataclass, field
from html import unescape
from html.parser import HTMLParser
from urllib.parse import urlencode, urljoin, urlparse

logger = logging.getLogger("wafer")

# ── ACW SC V2 Solver (Alibaba Cloud WAF) ──────────────────────────────────────
# The challenge page contains obfuscated JS, but after deobfuscation the shuffle
# table and XOR key are always the same across all sites. We extract arg1,
# shuffle, and XOR.

_ACW_SHUFFLE = [
    15, 35, 29, 24, 33, 16, 1, 38, 10, 9, 19, 31, 40, 27, 22, 23,
    25, 13, 6, 11, 39, 18, 20, 8, 14, 21, 32, 26, 2, 30, 7, 4,
    17, 5, 3, 28, 34, 37, 12, 36,
]
_ACW_KEY = "3000176000856006061501533003690027800375"


def solve_acw(body: str) -> str | None:
    """Solve ACW challenge: extract arg1, shuffle, XOR.

    Returns the cookie value (40-char hex string), or None if extraction fails.
    """
    match = re.search(r"var\s+arg1\s*=\s*'([0-9A-Fa-f]+)'", body)
    if not match:
        return None
    arg1 = match.group(1)

    if len(arg1) < max(_ACW_SHUFFLE):
        return None

    # Shuffle: output[i] = arg1[table[i] - 1]
    shuffled = "".join(arg1[v - 1] for v in _ACW_SHUFFLE)

    # XOR hex pairs with fixed key
    result = []
    for i in range(0, min(len(shuffled), len(_ACW_KEY)), 2):
        xored = int(shuffled[i : i + 2], 16) ^ int(
            _ACW_KEY[i : i + 2], 16
        )
        result.append(f"{xored:02x}")
    return "".join(result)


# ── Amazon Captcha Parser ─────────────────────────────────────────────────────
# Amazon's rate-limit interstitial has a "Continue shopping" link or form.
# No JS challenge, no image CAPTCHA -- just parse and follow.

_AMAZON_DOMAIN_RE = re.compile(
    r"(?:^|\.)(?:amazon|amzn)\."
    r"(?:com|ca|co\.uk|de|fr|it|es|co\.jp|com\.au|in|com\.br|com\.mx|"
    r"nl|sg|sa|ae|eg|pl|se|tr|to|com\.be|cn|com\.tr|com\.sg)$",
    re.IGNORECASE,
)


def _is_amazon_domain(url: str) -> bool:
    """Check if URL points to a known Amazon domain (SSRF protection)."""
    hostname = urlparse(url).hostname or ""
    return bool(_AMAZON_DOMAIN_RE.search(hostname))


class _FormParser(HTMLParser):
    """Parse HTML for links and forms (used for Amazon captcha pages)."""

    def __init__(self):
        super().__init__()
        self.links: list[tuple[str, str]] = []  # (href, text)
        self.forms: list[dict] = []
        self._current_form: dict | None = None
        self._link_href: str | None = None
        self._link_text = ""

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and "href" in a:
            self._link_href = a["href"]
            self._link_text = ""
        elif tag == "form":
            self._current_form = {
                "action": a.get("action", ""),
                "method": (a.get("method") or "GET").upper(),
                "fields": {},
            }
        elif tag == "input" and self._current_form is not None:
            name = a.get("name")
            if name:
                self._current_form["fields"][name] = a.get("value", "")

    def handle_endtag(self, tag):
        if tag == "a" and self._link_href is not None:
            self.links.append((self._link_href, self._link_text))
            self._link_href = None
        elif tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None

    def handle_data(self, data):
        if self._link_href is not None:
            self._link_text += data


def parse_amazon_captcha(body: str, page_url: str) -> dict | None:
    """Parse Amazon captcha page to extract submission target.

    Returns:
        Dict with 'method' ('GET'/'POST'), 'url' (absolute), 'params' (dict),
        or None if the page is unrecognized or target is non-Amazon.
    """
    parser = _FormParser()
    try:
        parser.feed(body)
    except Exception:
        return None

    # Strategy 1: "Continue shopping" link
    for href, text in parser.links:
        if "continue shopping" in text.lower():
            abs_url = urljoin(page_url, href)
            if _is_amazon_domain(abs_url):
                return {"method": "GET", "url": abs_url, "params": {}}

    # Strategy 2: Form with action + hidden fields
    for form in parser.forms:
        action = form["action"]
        abs_url = urljoin(page_url, action) if action else page_url
        if _is_amazon_domain(abs_url):
            return {
                "method": form["method"],
                "url": abs_url,
                "params": form["fields"],
            }

    return None


# ── TMD (Alibaba) ─────────────────────────────────────────────────────────────
# TMD just needs valid session cookies from the homepage. No JS execution.


def tmd_homepage_url(url: str) -> str:
    """Get homepage URL for TMD session warming."""
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}/"


# ── Reddit JSON session bootstrap ────────────────────────────────────────────

REDDIT_SOLVE_ORIGIN = "https://www.reddit.com/"
REDDIT_CACHE_DOMAIN = "reddit.com"
REDDIT_VERIFICATION_MAX_BYTES = 32 * 1024
# The live Shreddit network-security response was ~190 KiB on 2026-07-26,
# with its distinguishing block copy near the end. This cap is challenge
# overhead only; the caller's max_response_size still applies to the final
# response.
REDDIT_GATE_MAX_BYTES = 256 * 1024

_REDDIT_TITLE = "Reddit - Please wait for verification"
_REDDIT_FIELDS = frozenset({
    "solution",
    "js_challenge",
    "token",
    "jsc_orig_r",
})
_REDDIT_TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{16,256}\Z")
_REDDIT_CALC_RE = re.compile(
    r"""
    await\s*\(\s*async\s+
    (?P<var>[A-Za-z_$][A-Za-z0-9_$]*)\s*=>\s*
    (?P=var)\s*\+\s*(?P=var)\s*
    \)\s*\(\s*
    (?P<quote>["'])(?P<seed>[A-Za-z0-9]{1,128})(?P=quote)
    \s*\)
    """,
    re.VERBOSE,
)
_REDDIT_SCRIPT_MARKERS = (
    re.compile(r"document\.forms\s*\[\s*0\s*\]"),
    re.compile(
        r"\.elements\.namedItem\s*\(\s*([\"'])solution\1\s*\)"
        r"\.value\s*="
    ),
    re.compile(r"\.requestSubmit\s*\(\s*\)"),
)


@dataclass(frozen=True)
class RedditVerification:
    """Validated, internal New Reddit verification submission."""

    action_url: str
    fields: tuple[tuple[str, str], ...] = field(repr=False)


class _RedditDocumentParser(HTMLParser):
    """Collect only the small subset needed by Reddit verification."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms: list[dict] = []
        self.scripts: list[str] = []
        self.title_parts: list[str] = []
        self._form: dict | None = None
        self._script_parts: list[str] | None = None
        self._in_title = False

    def handle_starttag(self, tag, attrs):
        attrs_dict = {
            key.lower(): unescape(value or "")
            for key, value in attrs
        }
        tag = tag.lower()
        if tag == "title":
            self._in_title = True
        elif tag == "script":
            self._script_parts = []
        elif tag == "form":
            # Nested forms are invalid HTML and ambiguous for this solver.
            if self._form is not None:
                self.forms.append({"invalid": True})
            self._form = {
                "action": attrs_dict.get("action", ""),
                "method": (attrs_dict.get("method") or "GET").upper(),
                "fields": [],
            }
        elif tag == "input" and self._form is not None:
            self._form["fields"].append(
                {
                    "name": attrs_dict.get("name"),
                    "type": (attrs_dict.get("type") or "text").lower(),
                    "value": attrs_dict.get("value", ""),
                }
            )

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag == "title":
            self._in_title = False
        elif tag == "script" and self._script_parts is not None:
            self.scripts.append("".join(self._script_parts))
            self._script_parts = None
        elif tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None

    def handle_data(self, data):
        if self._in_title:
            self.title_parts.append(data)
        if self._script_parts is not None:
            self._script_parts.append(data)


def reddit_solve_origin(url: str) -> str | None:
    """Return the fixed New Reddit solve origin for a Reddit URL.

    Explicit Old Reddit requests remain explicit requests. This helper only
    selects the origin used after a recognized Reddit JSON session gate.
    """
    host = (urlparse(url).hostname or "").rstrip(".").lower()
    if host == "reddit.com" or host.endswith(".reddit.com"):
        return REDDIT_SOLVE_ORIGIN
    return None


def reddit_cookie_names(raw_values) -> frozenset[str]:
    """Extract Set-Cookie names without retaining or exposing values."""
    names = set()
    for raw in raw_values:
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="replace")
        else:
            raw = str(raw)
        name, separator, _ = raw.partition("=")
        name = name.strip()
        if separator and name:
            names.add(name)
    return frozenset(names)


def reddit_has_cookie_evidence(names) -> bool:
    """Whether response-scoped cookie names prove anonymous setup."""
    names = frozenset(names)
    return "loid" in names and bool({"token_v2", "csv"} & names)


def _validated_reddit_action(action: str) -> str | None:
    try:
        parsed = urlparse(urljoin(REDDIT_SOLVE_ORIGIN, action))
        port = parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme != "https"
        or (parsed.hostname or "").rstrip(".").lower() != "www.reddit.com"
        or port not in (None, 443)
        or parsed.path != "/"
        or parsed.params
        or parsed.query
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
    ):
        return None
    return REDDIT_SOLVE_ORIGIN


def parse_reddit_verification(body: str) -> RedditVerification | None:
    """Parse the recognized logged-out verification without executing JS."""
    parser = _RedditDocumentParser()
    try:
        parser.feed(body)
        parser.close()
    except Exception:
        return None

    title = " ".join("".join(parser.title_parts).split())
    if title != _REDDIT_TITLE or len(parser.forms) != 1:
        return None

    form = parser.forms[0]
    if form.get("invalid") or form.get("method") != "GET":
        return None
    action_url = _validated_reddit_action(form.get("action", ""))
    if action_url is None:
        return None

    fields = form.get("fields", [])
    if (
        len(fields) != len(_REDDIT_FIELDS)
        or any(field["type"] != "hidden" for field in fields)
    ):
        return None
    names = [field["name"] for field in fields]
    if None in names or set(names) != _REDDIT_FIELDS:
        return None
    if len(names) != len(set(names)):
        return None
    by_name = {field["name"]: field["value"] for field in fields}
    if (
        by_name["solution"] != ""
        or by_name["js_challenge"] != "1"
        or by_name["jsc_orig_r"] != ""
        or not _REDDIT_TOKEN_RE.fullmatch(by_name["token"])
    ):
        return None

    calculations = []
    matching_scripts = []
    for script in parser.scripts:
        matches = list(_REDDIT_CALC_RE.finditer(script))
        calculations.extend(matches)
        if matches:
            matching_scripts.append(script)
    if len(calculations) != 1 or len(matching_scripts) != 1:
        return None
    script = matching_scripts[0]
    if any(marker.search(script) is None for marker in _REDDIT_SCRIPT_MARKERS):
        return None

    seed = unescape(calculations[0].group("seed"))
    if not re.fullmatch(r"[A-Za-z0-9]{1,128}", seed):
        return None
    solution = seed + seed
    solved_fields = tuple(
        (field["name"], solution if field["name"] == "solution" else field["value"])
        for field in fields
    )
    return RedditVerification(action_url=action_url, fields=solved_fields)


def reddit_submission_url(verification: RedditVerification) -> str:
    """Build the solved query URL. Callers must never log the result."""
    return f"{verification.action_url}?{urlencode(verification.fields)}"
