"""Inline challenge solvers -- pure Python, no browser needed.

ACW: Alibaba Cloud WAF -- shuffle + XOR (~1ms)
PoW: home-grown SHA-256 proof-of-work gate -- hash loop + cookie (~1ms)
Amazon: Rate-limit captcha -- form parsing + submission (~100ms)
TMD: Alibaba TMD -- session warming via homepage fetch
Reddit: Logged-out verification form parsing + solution derivation
"""

import hashlib
import logging
import re
import time
from dataclasses import dataclass, field
from html import unescape
from html.parser import HTMLParser
from urllib.parse import urlencode, urljoin, urlparse

from wafer._cookies import cookie_domain_matches, registrable_domain

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


# ── Proof-of-work gate ────────────────────────────────────────────────────────
# A home-grown Varnish-fronted gate (measured on redflagdeals.com, both the
# www and forums hosts) that answers every page with HTTP 202 and a <head>
# holding one inline script. The script hashes ``nonce + issued_at + counter``
# with SHA-256 until the hex digest starts with ``difficulty_char`` repeated
# ``difficulty`` times, then writes a ``pow_bypass`` cookie and reloads. No
# vendor, no browser, no CAPTCHA: pure computation, then replay on the same
# jar. See docs/ref-pow.md.

POW_COOKIE_NAME = "pow_bypass"

# The measured page is 2,671 bytes and is nothing but the script. Anything
# larger is a real document, and the cap also bounds how much of a body the
# parser ever scans, so a hostile page cannot buy CPU with size.
POW_MAX_PAGE_BYTES = 50_000

# The page script gives up after 1e7 counters; there is no point outlasting
# it. Difficulty is capped so a hostile or misconfigured page cannot ask for
# work the ceiling rarely or never satisfies. Measured ~3M SHA-256/s here: 5
# nibbles expects ~1M hashes (a third of a second) and the ceiling fails fewer
# than 1 in 10,000 such solves, while 6 expects ~16.8M, more than the ceiling
# itself, so it would spend the whole ceiling (~3 s) and then usually fail.
_POW_MAX_ITERATIONS = 10_000_000
_POW_MAX_DIFFICULTY = 5
# How often the hash loop looks at the clock. With the preimage bounded to a
# few hundred bytes this is well under a millisecond between checks.
_POW_DEADLINE_STRIDE = 4096

# ``[^{}]*`` cannot backtrack across braces, so a body stuffed with unclosed
# ``POW_CHALLENGE_DATA={`` costs one short scan per occurrence, not one scan
# to end-of-body each (the naive ``(.*?)\}`` form is quadratic).
_POW_DATA_RE = re.compile(r"POW_CHALLENGE_DATA\s*=\s*\{([^{}]*)\}")
# Detection form: the object must open inside a <script> element, with nothing
# but script text between the tag and the assignment. Prose that quotes the
# object, and an HTML-rendered doc whose tags are escaped, both fail this;
# the real page is exactly ``<script>\n window.POW_CHALLENGE_DATA={``.
# The attribute scan is bounded (``{0,512}``) so a body stuffed with ``<script``
# and no ``>`` costs at most 512 chars per occurrence instead of a scan to
# end-of-body each; with that, and ``[^<]*`` / ``[^{}]*`` unable to cross
# their delimiters, every start position does bounded work.
_POW_SCRIPT_RE = re.compile(
    r"<script[^>]{0,512}>[^<]*POW_CHALLENGE_DATA\s*=\s*\{[^{}]*\}", re.IGNORECASE
)
_POW_FIELD_RE = re.compile(r"(\w+)\s*:\s*'([^']*)'")
# Real values: nonce 32 hex, hmac 24 hex. Bounded so a page cannot hand back
# a megabyte cookie, bloat the cache file, or stretch the hash preimage until
# the deadline stride is no longer fine-grained.
_POW_HEX_RE = re.compile(r"[0-9a-f]{16,128}\Z")
_POW_NIBBLE_RE = re.compile(r"[0-9a-f]\Z")
_POW_ISSUED_RE = re.compile(r"[0-9]{1,20}\Z")
_POW_DIFFICULTY_RE = re.compile(r"[0-9]{1,2}\Z")
_POW_DURATION_RE = re.compile(r"[0-9]{1,10}\Z")
_POW_DOMAIN_RE = re.compile(r"\.?[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+\Z")
# The page's cookie_duration is 3,600. Fallback when the field is absent or
# zero (a zero-lifetime cookie would expire before the reload that needs it,
# so the page cannot mean it), and a ceiling so a page cannot pin a cookie in
# the cache for years.
_POW_DEFAULT_MAX_AGE = 3600
_POW_MAX_MAX_AGE = 86_400


def is_pow_challenge(body: str) -> bool:
    """True for a proof-of-work gate page.

    Structural, not textual: the page must be small (the real one is 2.7 KB
    and is only the script), open the ``POW_CHALLENGE_DATA`` object inside a
    ``<script>`` element, and name the ``pow_bypass`` cookie. A page that
    merely quotes the object - a bug report, this project's own docs, a forum
    thread about the gate - has no script element wrapping it, and a real
    document that embeds all of it fails the size cap.

    The cookie name is required because it is what the solver writes: a
    variant of this gate that names its cookie differently would be detected
    and then "solved" with the wrong cookie, which is worse than the plain
    replay the loop falls back to. Nothing else about the script's text is
    assumed (not even how it reaches ``document.cookie``), so an obfuscation
    pass over the script does not silently turn the gate back into content.
    """
    if len(body) > POW_MAX_PAGE_BYTES:
        return False
    if "POW_CHALLENGE_DATA" not in body or POW_COOKIE_NAME not in body:
        return False
    return _POW_SCRIPT_RE.search(body) is not None


@dataclass(frozen=True)
class PowSolution:
    """A solved proof-of-work gate, ready to add to a cookie jar."""

    cookie: str
    """The full Set-Cookie string the page script would have written."""

    name: str
    """Cookie name (``pow_bypass``)."""

    max_age: int
    """Cookie lifetime in seconds, from the page's ``cookie_duration``."""

    iterations: int
    """The counter that produced the winning digest."""


def parse_pow_challenge(body: str) -> dict[str, str] | None:
    """Extract and validate the ``POW_CHALLENGE_DATA`` object from a gate page.

    Returns the field map, or ``None`` if the object is missing or any field
    the solve depends on is malformed. Validation is strict on purpose: the
    values are concatenated into a hash preimage and echoed into a cookie, so
    anything that is not the shape the real script produces is refused rather
    than guessed at. Only the first ``POW_MAX_PAGE_BYTES`` are scanned.
    """
    m = _POW_DATA_RE.search(body[:POW_MAX_PAGE_BYTES])
    if not m:
        return None
    fields = dict(_POW_FIELD_RE.findall(m.group(1)))
    nonce = fields.get("challenge_nonce", "")
    hmac = fields.get("challenge_hmac", "")
    issued_at = fields.get("issued_at", "")
    difficulty = fields.get("difficulty", "")
    difficulty_char = fields.get("difficulty_char", "")
    if not _POW_HEX_RE.match(nonce) or not _POW_HEX_RE.match(hmac):
        return None
    if not _POW_ISSUED_RE.match(issued_at):
        return None
    if not _POW_DIFFICULTY_RE.match(difficulty) or not (
        1 <= int(difficulty) <= _POW_MAX_DIFFICULTY
    ):
        return None
    # The digest is lower-case hex, so any other prefix character can never
    # match and the loop would spin to the ceiling for nothing.
    if not _POW_NIBBLE_RE.match(difficulty_char):
        return None
    duration = fields.get("cookie_duration", "")
    if duration and not _POW_DURATION_RE.match(duration):
        return None
    domain = fields.get("cookie_domain", "")
    if domain and not _POW_DOMAIN_RE.match(domain):
        return None
    return fields


def _pow_cookie_domain(cookie_domain: str, url: str) -> str | None:
    """The ``Domain`` attribute to write, or ``None`` for a host-only cookie.

    The page names its own parent domain (``.redflagdeals.com``), which is
    what lets one solve cover both the www and forums hosts. It is honoured
    only when the request host is that domain or under it AND the domain is
    at or below the host's registrable domain. wreq's jar does NOT enforce a
    public-suffix boundary (measured: it accepts ``Domain=co.uk`` from
    ``evil.co.uk``), so without the second check a page on a shared suffix
    such as ``github.io`` could plant a cookie every sibling site receives.
    Anything refused degrades to a host-only cookie, which the gate accepts.
    """
    host = (urlparse(url).hostname or "").lower().rstrip(".")
    domain = cookie_domain.lower().lstrip(".").rstrip(".")
    if not host or not domain:
        return None
    if host != domain and not host.endswith("." + domain):
        return None
    if not cookie_domain_matches(domain, registrable_domain(host)):
        return None
    return domain


def solve_pow(
    body: str, url: str, deadline: float | None = None
) -> PowSolution | None:
    """Solve a proof-of-work gate page. Returns the cookie to replay with.

    Mirrors the page script exactly: counter as decimal text from 1, preimage
    ``nonce + issued_at + counter`` with no separator, lower-case hex SHA-256,
    prefix comparison. The cookie carries the five fields the script writes
    for a clean browser (``nonce|issued_at|counter|digest|hmac``) and no
    trailing signals field - the script only appends one when a headless
    signal fires, so a sixth field is a shape a passing browser never sends.

    ``deadline`` is a ``time.monotonic()`` instant; the loop returns ``None``
    once it passes. ``None`` is also returned if the page is malformed or the
    script's own 1e7 ceiling is reached.
    """
    fields = parse_pow_challenge(body)
    if fields is None:
        logger.debug("PoW gate page present but POW_CHALLENGE_DATA malformed")
        return None
    nonce = fields["challenge_nonce"]
    issued_at = fields["issued_at"]
    prefix = fields["difficulty_char"] * int(fields["difficulty"])
    seed = (nonce + issued_at).encode()

    counter = 0
    digest = None
    while counter < _POW_MAX_ITERATIONS:
        if (
            deadline is not None
            and counter % _POW_DEADLINE_STRIDE == 0
            and time.monotonic() >= deadline
        ):
            logger.debug("PoW solve abandoned at counter %d: deadline", counter)
            return None
        counter += 1
        h = hashlib.sha256(seed + str(counter).encode()).hexdigest()
        if h.startswith(prefix):
            digest = h
            break
    if digest is None:
        logger.debug("PoW solve hit the %d-iteration ceiling", _POW_MAX_ITERATIONS)
        return None

    value = "|".join(
        (nonce, issued_at, str(counter), digest, fields["challenge_hmac"])
    )
    duration = fields.get("cookie_duration", "")
    max_age = int(duration) if duration else 0
    if max_age <= 0:
        max_age = _POW_DEFAULT_MAX_AGE
    max_age = min(max_age, _POW_MAX_MAX_AGE)
    parts = [f"{POW_COOKIE_NAME}={value}"]
    domain = _pow_cookie_domain(fields.get("cookie_domain", ""), url)
    if domain:
        parts.append(f"Domain={domain}")
    parts.append("Path=/")
    parts.append(f"Max-Age={max_age}")
    parts.append("SameSite=Lax")
    if urlparse(url).scheme == "https":
        parts.append("Secure")
    return PowSolution(
        cookie="; ".join(parts),
        name=POW_COOKIE_NAME,
        max_age=max_age,
        iterations=counter,
    )


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

# Value-free outcome labels for one anonymous-bootstrap attempt. Surfaced by
# BaseSession.reddit_bootstrap_state() and used in the bootstrap's log lines so
# a failed anonymous setup names the branch that produced it.
REDDIT_OUTCOME_ESTABLISHED = "established"
REDDIT_OUTCOME_VERIFICATION_STATUS = "verification_status"
REDDIT_OUTCOME_VERIFICATION_TOO_LARGE = "verification_too_large"
REDDIT_OUTCOME_VERIFICATION_ENCODING = "verification_encoding"
REDDIT_OUTCOME_VERIFICATION_STRUCTURE = "verification_structure"
REDDIT_OUTCOME_SUBMISSION_STATUS = "submission_status"
REDDIT_OUTCOME_COOKIE_EVIDENCE = "cookie_evidence"
REDDIT_OUTCOME_TRANSPORT = "transport"
REDDIT_OUTCOME_CLIENT_ROTATED = "client_rotated"
REDDIT_BROWSER_OUTCOME_ESTABLISHED = "established"
REDDIT_BROWSER_OUTCOME_FAILED = "failed"
REDDIT_BROWSER_OUTCOME_NO_TIME_BUDGET = "no_time_budget"
REDDIT_BROWSER_OUTCOME_UNAVAILABLE = "unavailable"
# Recorded when the recovery starts, and left in place only by a solver that
# raised: every normal return overwrites it with a real outcome.
REDDIT_BROWSER_OUTCOME_INTERRUPTED = "interrupted"

# Cookie names are safe to report (unlike values), but they arrive from a
# response header, so bound the count and reject anything outside the RFC 6265
# token characters actually used by Reddit rather than putting header bytes in
# a log line.
_REDDIT_MAX_REPORTED_COOKIE_NAMES = 32
_REDDIT_SAFE_COOKIE_NAME = re.compile(r"[A-Za-z0-9_.-]{1,64}")

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


def reddit_cookie_name_summary(names) -> tuple[str, ...]:
    """Sort and bound cookie names for logs and diagnostics.

    Names only; a value never reaches this function. Names that are not plain
    tokens are dropped: they cannot be part of Reddit's anonymous cookie set,
    and reporting them would put arbitrary header bytes in a log line. Decide
    cookie evidence from the full set, never from this summary.
    """
    safe = sorted(
        name
        for name in names
        if _REDDIT_SAFE_COOKIE_NAME.fullmatch(str(name))
    )
    return tuple(safe[:_REDDIT_MAX_REPORTED_COOKIE_NAMES])


def format_reddit_cookie_names(names) -> str:
    """Render a cookie-name summary for one log line."""
    return ",".join(reddit_cookie_name_summary(names)) or "none"


def reddit_has_cookie_evidence(names) -> bool:
    """Whether response-scoped cookie names prove anonymous setup."""
    names = frozenset(names)
    return "loid" in names and bool({"token_v2", "csv"} & names)


def _validated_reddit_action(
    action: str,
    *,
    allow_same_origin_path: bool = False,
) -> str | None:
    try:
        parsed = urlparse(urljoin(REDDIT_SOLVE_ORIGIN, action))
        port = parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme != "https"
        or (parsed.hostname or "").rstrip(".").lower() != "www.reddit.com"
        or port not in (None, 443)
        or (
            parsed.path != "/"
            and not (
                allow_same_origin_path
                and parsed.path.startswith("/")
            )
        )
        or parsed.params
        or parsed.query
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
    ):
        return None
    if allow_same_origin_path:
        return parsed.geturl()
    return REDDIT_SOLVE_ORIGIN


def _parse_reddit_verification(
    body: str,
    *,
    allow_same_origin_path: bool,
) -> RedditVerification | None:
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
    action_url = _validated_reddit_action(
        form.get("action", ""),
        allow_same_origin_path=allow_same_origin_path,
    )
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


def parse_reddit_verification(body: str) -> RedditVerification | None:
    """Parse the fixed-origin verification used by the bootstrap submit."""
    return _parse_reddit_verification(
        body,
        allow_same_origin_path=False,
    )


def is_reddit_verification(body: str) -> bool:
    """Recognize a direct Reddit verification for any same-origin path."""
    return (
        _parse_reddit_verification(
            body,
            allow_same_origin_path=True,
        )
        is not None
    )


def reddit_submission_url(verification: RedditVerification) -> str:
    """Build the solved query URL. Callers must never log the result."""
    return f"{verification.action_url}?{urlencode(verification.fields)}"
