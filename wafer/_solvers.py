"""Inline challenge solvers -- pure Python, no browser needed.

ACW: Alibaba Cloud WAF -- shuffle + XOR (~1ms)
Amazon: Rate-limit captcha -- form parsing + submission (~100ms)
TMD: Alibaba TMD -- session warming via homepage fetch
"""

import logging
import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

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
