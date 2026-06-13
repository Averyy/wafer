"""Browser-free reCAPTCHA v3 token minting.

reCAPTCHA v3 returns a *score* token rather than asking the user to solve a
challenge. The token is minted by two cross-origin requests to Google's
reCAPTCHA endpoints (no browser, no JS execution):

1. ``GET .../anchor`` -- returns an HTML page carrying a hidden
   ``recaptcha-token`` input (the anchor/``c`` token).
2. ``POST .../reload`` -- exchanges the anchor token for the final
   response token, embedded in the JSON-ish body as ``["rresp","<token>"]``.

The token is minted under the session's own TLS-emulated client, so it
rides a real browser fingerprint. The flow keys only off values readable
from the embedding page: the sitekey, the action name, and the origin.

Caveat: minting always produces a token, but the *score* Google assigns it
depends on request reputation (IP, TLS shape, cookies). wafer mints the
token; it cannot guarantee the site's score threshold passes.
"""

import base64
import logging
import os
import re
import urllib.parse

from wafer._errors import TokenMintFailed

logger = logging.getLogger("wafer")

_GOOGLE = "https://www.google.com"

# The <input> carrying the anchor (c) token in the anchor page HTML.
# Two-pass: locate the recaptcha-token input tag, then read its value, so
# attribute order (id-before-value or value-before-id) and quote style
# don't matter.
_ANCHOR_INPUT_RE = re.compile(
    r'<input[^>]*\b(?:id|name)=["\']recaptcha-token["\'][^>]*>',
    re.IGNORECASE,
)
_ANCHOR_VALUE_RE = re.compile(r'\bvalue=["\']([^"\']+)["\']', re.IGNORECASE)
# Final response token in the reload body, e.g. ["rresp","03AGd..."].
_RELOAD_TOKEN_RE = re.compile(r'\["rresp","([^"]+)"')
# Release hash in the api.js loader, e.g. .../releases/<v>/recaptcha__en.js
_RELEASE_RE = re.compile(r"releases/([\w-]+)/")

# Alphabet for the random cb callback id, matching Google's loader (the
# loader builds an 18-char [A-Za-z0-9] id). We derive it from os.urandom
# rather than Math.random/Date so it varies per call without being
# predictable.
_CB_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
_CB_LEN = 18


def compute_co(origin: str) -> str:
    """Compute the ``co`` param: base64url(scheme://host:port), Google-style.

    Google encodes the origin as standard base64url then replaces the
    ``=`` padding with ``.`` (e.g. ``https://www.bell.ca`` ->
    ``aHR0cHM6Ly93d3cuYmVsbC5jYTo0NDM.``). The origin is normalized to
    scheme + host (+ explicit non-default port); any path/query is
    dropped.
    """
    # Accept a bare host (no scheme) by assuming https.
    src = origin if "://" in origin else "https://" + origin.strip().rstrip("/")
    parsed = urllib.parse.urlsplit(src)
    scheme = (parsed.scheme or "https").lower()
    host = (parsed.hostname or "").lower()
    if not host:
        raise TokenMintFailed(
            f"cannot parse reCAPTCHA origin {origin!r}", stage="anchor"
        )
    # Google encodes scheme://host:port using the origin's ACTUAL port
    # (explicit if given, else the scheme default) -- not unconditionally
    # :443, which would double a non-default port or mislabel http.
    port = parsed.port or (443 if scheme == "https" else 80)
    raw = f"{scheme}://{host}:{port}".encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").replace("=", ".")


def generate_cb(seed: bytes | None = None) -> str:
    """Generate the 18-char alphanumeric ``cb`` callback id.

    Built from ``os.urandom`` (or ``seed`` when provided, for
    determinism in tests) -- varies per call, no Math.random/Date.
    """
    raw = seed if seed is not None else os.urandom(_CB_LEN)
    n = len(_CB_ALPHABET)
    return "".join(_CB_ALPHABET[b % n] for b in raw[:_CB_LEN]).ljust(
        _CB_LEN, _CB_ALPHABET[0]
    )[:_CB_LEN]


def origin_from_referer(referer: str) -> str:
    """Derive ``scheme://host[:port]`` origin from a referer URL."""
    parsed = urllib.parse.urlsplit(referer)
    if not parsed.scheme or not parsed.netloc:
        raise TokenMintFailed(
            f"cannot derive origin from referer {referer!r}",
            stage="anchor",
        )
    return f"{parsed.scheme}://{parsed.netloc}"


def _paths(enterprise: bool) -> tuple[str, str, str]:
    """Return (anchor_path, reload_path, apijs_filename) for the mode."""
    if enterprise:
        return (
            "/recaptcha/enterprise/anchor",
            "/recaptcha/enterprise/reload",
            "enterprise.js",
        )
    return ("/recaptcha/api2/anchor", "/recaptcha/api2/reload", "api.js")


def build_anchor_url(
    sitekey: str,
    *,
    co: str,
    v: str,
    cb: str,
    enterprise: bool = False,
) -> str:
    """Build the anchor GET URL (invisible v3 widget)."""
    anchor_path, _, _ = _paths(enterprise)
    query = urllib.parse.urlencode(
        {
            "ar": "1",
            "k": sitekey,
            "co": co,
            "hl": "en",
            "v": v,
            "size": "invisible",
            "cb": cb,
        }
    )
    return f"{_GOOGLE}{anchor_path}?{query}"


def build_reload_url(sitekey: str, *, enterprise: bool = False) -> str:
    """Build the reload POST URL (sitekey in the query string)."""
    _, reload_path, _ = _paths(enterprise)
    return f"{_GOOGLE}{reload_path}?k={urllib.parse.quote(sitekey)}"


def build_reload_body(
    sitekey: str,
    *,
    co: str,
    v: str,
    action: str,
    anchor_token: str,
) -> str:
    """Build the form-urlencoded reload POST body.

    The action rides in ``sa`` (there is no ``chr`` param). ``reason=q``
    is the standard "query" reason for an invisible v3 widget.
    """
    return urllib.parse.urlencode(
        {
            "v": v,
            "reason": "q",
            "c": anchor_token,
            "k": sitekey,
            "co": co,
            "hl": "en",
            "size": "invisible",
            "sa": action,
        }
    )


def apijs_url(enterprise: bool = False) -> str:
    """URL of the reCAPTCHA api.js / enterprise.js loader."""
    _, _, filename = _paths(enterprise)
    return f"{_GOOGLE}/recaptcha/{filename}"


def parse_release_version(api_js: str) -> str:
    """Extract the release hash (``v``) from an api.js/enterprise.js body."""
    match = _RELEASE_RE.search(api_js)
    if not match:
        raise TokenMintFailed(
            "could not scrape reCAPTCHA release version from api.js "
            f"(len={len(api_js)})",
            stage="apijs",
        )
    return match.group(1)


def parse_anchor_token(html: str, status_code: int) -> str:
    """Extract the anchor (c) token from the anchor page HTML."""
    tag = _ANCHOR_INPUT_RE.search(html)
    val = _ANCHOR_VALUE_RE.search(tag.group(0)) if tag else None
    if val is None:
        raise TokenMintFailed(
            "reCAPTCHA anchor token not found "
            f"(status={status_code}, len={len(html)})",
            stage="anchor",
            status_code=status_code,
        )
    return val.group(1)


def parse_reload_token(body: str, status_code: int) -> str:
    """Extract the final response token from the reload body."""
    match = _RELOAD_TOKEN_RE.search(body)
    if not match:
        raise TokenMintFailed(
            "reCAPTCHA reload response token not found "
            f"(status={status_code}, len={len(body)})",
            stage="reload",
            status_code=status_code,
        )
    return match.group(1)


def _resolve_origin_referer(
    origin: str | None, referer: str | None
) -> tuple[str, str]:
    """Resolve the (origin, referer) pair from the caller's inputs.

    - origin given, referer None -> referer defaults to origin
    - referer given, origin None -> origin derived from referer
    - both given -> used as-is
    - neither -> error
    """
    if origin is None and referer is None:
        raise TokenMintFailed(
            "mint_recaptcha_v3 requires origin or referer",
            stage="anchor",
        )
    if origin is None:
        origin = origin_from_referer(referer)  # type: ignore[arg-type]
    if referer is None:
        referer = origin
    return origin, referer


def _prepare(
    sitekey: str,
    action: str,
    origin: str | None,
    referer: str | None,
    enterprise: bool,
    cb_seed: bytes | None,
) -> dict:
    """Build the immutable request plan shared by the sync/async flows.

    Returns a dict of everything except ``v`` (resolved separately, since
    scraping it may need an HTTP round-trip) and the anchor token (minted
    in the flow).
    """
    origin, referer = _resolve_origin_referer(origin, referer)
    co = compute_co(origin)
    return {
        "sitekey": sitekey,
        "action": action,
        "origin": origin,
        "referer": referer,
        "co": co,
        "cb": generate_cb(cb_seed),
        "enterprise": enterprise,
    }


def mint_sync(
    request_fn,
    sitekey: str,
    action: str,
    *,
    origin: str | None = None,
    referer: str | None = None,
    v: str | None = None,
    enterprise: bool = False,
    scrape_v=None,
    cb_seed: bytes | None = None,
) -> str:
    """Mint a reCAPTCHA v3 token using a synchronous ``request_fn``.

    ``request_fn(method, url, **kwargs)`` must return a response object
    exposing ``.status_code`` and ``.text`` (a wafer session ``request``
    method). ``scrape_v()`` is called to resolve+cache ``v`` when not
    supplied; it must return the release version string.
    """
    plan = _prepare(sitekey, action, origin, referer, enterprise, cb_seed)
    if v is None:
        if scrape_v is None:
            v = _scrape_v_sync(request_fn, enterprise)
        else:
            v = scrape_v()

    anchor_url = build_anchor_url(
        plan["sitekey"],
        co=plan["co"],
        v=v,
        cb=plan["cb"],
        enterprise=enterprise,
    )
    anchor_resp = request_fn(
        "GET", anchor_url, headers={"Referer": plan["referer"]}
    )
    anchor_token = parse_anchor_token(
        anchor_resp.text, anchor_resp.status_code
    )

    reload_resp = request_fn(
        "POST",
        build_reload_url(plan["sitekey"], enterprise=enterprise),
        headers={
            # The reload call is an XHR in a real browser, not a navigation,
            # so it sends Accept: */* (not the session's text/html default).
            "Accept": "*/*",
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": _GOOGLE,
            "Referer": anchor_url,
        },
        body=build_reload_body(
            plan["sitekey"],
            co=plan["co"],
            v=v,
            action=plan["action"],
            anchor_token=anchor_token,
        ),
    )
    token = parse_reload_token(reload_resp.text, reload_resp.status_code)
    logger.debug(
        "minted reCAPTCHA v3 token len=%d action=%r enterprise=%s",
        len(token),
        plan["action"],
        enterprise,
    )
    return token


async def mint_async(
    request_fn,
    sitekey: str,
    action: str,
    *,
    origin: str | None = None,
    referer: str | None = None,
    v: str | None = None,
    enterprise: bool = False,
    scrape_v=None,
    cb_seed: bytes | None = None,
) -> str:
    """Async parity of :func:`mint_sync`.

    ``request_fn`` and ``scrape_v`` are awaitable.
    """
    plan = _prepare(sitekey, action, origin, referer, enterprise, cb_seed)
    if v is None:
        if scrape_v is None:
            v = await _scrape_v_async(request_fn, enterprise)
        else:
            v = await scrape_v()

    anchor_url = build_anchor_url(
        plan["sitekey"],
        co=plan["co"],
        v=v,
        cb=plan["cb"],
        enterprise=enterprise,
    )
    anchor_resp = await request_fn(
        "GET", anchor_url, headers={"Referer": plan["referer"]}
    )
    anchor_token = parse_anchor_token(
        anchor_resp.text, anchor_resp.status_code
    )

    reload_resp = await request_fn(
        "POST",
        build_reload_url(plan["sitekey"], enterprise=enterprise),
        headers={
            # The reload call is an XHR in a real browser, not a navigation,
            # so it sends Accept: */* (not the session's text/html default).
            "Accept": "*/*",
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": _GOOGLE,
            "Referer": anchor_url,
        },
        body=build_reload_body(
            plan["sitekey"],
            co=plan["co"],
            v=v,
            action=plan["action"],
            anchor_token=anchor_token,
        ),
    )
    token = parse_reload_token(reload_resp.text, reload_resp.status_code)
    logger.debug(
        "minted reCAPTCHA v3 token len=%d action=%r enterprise=%s",
        len(token),
        plan["action"],
        enterprise,
    )
    return token


def _scrape_v_sync(request_fn, enterprise: bool) -> str:
    """Fetch api.js and parse its release version (sync request_fn)."""
    resp = request_fn("GET", apijs_url(enterprise))
    if resp.status_code != 200:
        raise TokenMintFailed(
            f"api.js fetch failed (status={resp.status_code})",
            stage="apijs",
            status_code=resp.status_code,
        )
    return parse_release_version(resp.text)


async def _scrape_v_async(request_fn, enterprise: bool) -> str:
    """Fetch api.js and parse its release version (async request_fn)."""
    resp = await request_fn("GET", apijs_url(enterprise))
    if resp.status_code != 200:
        raise TokenMintFailed(
            f"api.js fetch failed (status={resp.status_code})",
            stage="apijs",
            status_code=resp.status_code,
        )
    return parse_release_version(resp.text)
