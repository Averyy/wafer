"""Challenge detection for 20 WAF types.

Pure logic, no I/O. Inspects status code, headers, and body to identify
which WAF/challenge system is blocking a request.

Detection order is intentional:
1. Inline-solvable challenges first (ACW, TMD, Amazon, Reddit)
2. Browser-solvable challenges next (Cloudflare, Akamai, DataDome, etc.)
3. Generic JS fallback last
"""

import enum
import logging
from urllib.parse import urlparse

from wafer._solvers import is_reddit_verification

logger = logging.getLogger("wafer")

# JS hooks unique to the modern reese "Pardon Our Interruption" interstitial -
# the page that carries the reese84 sensor. They never appear on real content
# pages, so they hold at any body size. Shared with the browser solver, which
# reads them as proof the challenged host will hand a browser a challenge it
# can pass in place (see wafer/browser/_imperva.py).
IMPERVA_INTERSTITIAL_HOOKS = (
    "reeseskipexpirationcheck",
    "__imperva_interstitial_started__",
    'id="interstitial-inprogress"',
    "x-spa-interstitial",
)


def is_imperva_interstitial(body: str) -> bool:
    """True for the reese sensor interstitial, which a browser can solve in place.

    Requires both the Imperva resource loader and an interstitial-only hook.
    The loader alone appears on real protected pages too, and a hookless
    Imperva block (e.g. the ``edet=15`` "Access Denied" page an API host
    returns) carries no sensor to run - neither is solvable by navigating the
    challenged URL.
    """
    body_lower = body.lower()
    return "_incapsula_resource" in body_lower and any(
        hook in body_lower for hook in IMPERVA_INTERSTITIAL_HOOKS
    )


# Radware Bot Manager (the vendor formerly shipped as ShieldSquare) splits
# cleanly into a sensor that rides on ORDINARY protected pages and a captcha
# template that only ever appears on a block.
#
# The sensor bootstrap is the loader: it declares ``SSJSConnectorObj`` and the
# ``__uzdbm_*`` globals, then pulls Radware's behavioural script. Measured on
# gojobs.gov.on.ca, it is present on the real job page as well as the block -
# exactly like Imperva's _Incapsula_Resource - so it identifies the vendor and
# nothing more. The same goes for the ``__uzm*`` cookie family: the successful
# page sets __uzmc/__uzmd/__uzmf of its own accord, so keying detection on the
# cookies (or on the sensor) would re-flag every page the site serves and spin
# the retry loop forever.
RADWARE_SENSOR_MARKERS = (
    "ssjsconnectorobj",
    "__uzdbm_",
)

# Template-only markers, none of which appear on a real protected page:
# ``captcha.perfdrive.com`` hosts the captcha stylesheet and its ss_captcha.png
# artwork, "shieldsquare" survives in that stylesheet's filename,
# ``SSJSInternal`` is set only by the challenge document, and the title is the
# vendor's own brand string.
RADWARE_CHALLENGE_MARKERS = (
    "captcha.perfdrive.com",
    "shieldsquare",
    "ssjsinternal",
    "radware captcha page",
)


# Radware's bot-management infrastructure. A blocked request is answered by the
# ORIGIN with a 3xx into this domain, and the captcha is then served from
# validate.perfdrive.com. A site has no reason to redirect a visitor into the
# vendor's host for anything else, which is what makes this signal safe on its
# own where the sensor and cookie markers are not.
RADWARE_CHALLENGE_DOMAIN = "perfdrive.com"


def is_radware_challenge_redirect(location: str) -> bool:
    """True for the 3xx hop that fronts the Radware captcha.

    Only a ``follow_redirects=False`` caller ever sees this: with redirects on,
    wafer follows the hop internally and classifies the captcha page instead.
    It matters because that redirect is where the ``__uzm*`` clearance is
    issued, so a caller can replay straight from here and never fetch the
    captcha at all.
    """
    if not location:
        return False
    parsed = urlparse(location)
    # Only a web redirect can be a challenge hop. ``urlparse`` resolves
    # userinfo correctly - "https://validate.perfdrive.com@evil.com/" has
    # hostname evil.com and is rejected here, which is the direction that
    # matters.
    if parsed.scheme not in ("http", "https"):
        return False
    host = (parsed.hostname or "").lower().rstrip(".")
    return host == RADWARE_CHALLENGE_DOMAIN or host.endswith(
        "." + RADWARE_CHALLENGE_DOMAIN
    )


def _matches_radware_markers(body_lower: str) -> bool:
    """Marker test against an ALREADY-lowercased body.

    Split out so ``detect_challenge`` can reuse the single ``body_lower`` it
    computes for every response. Lowercasing an 85KB body costs ~0.14ms and is
    linear in body size, so doing it a second time here would have added that
    to every response wafer handles, Radware-protected or not.
    """
    return any(m in body_lower for m in RADWARE_SENSOR_MARKERS) and any(
        m in body_lower for m in RADWARE_CHALLENGE_MARKERS
    )


def is_radware_challenge(body: str) -> bool:
    """True for the Radware Bot Manager captcha interstitial.

    Requires the sensor bootstrap AND a captcha-template marker. Either half
    alone is unsafe: the sensor rides on real content, and a bare template
    string could be quoted by a page merely writing about the vendor. Demanding
    both is what keeps a solved Radware site from re-detecting on every
    subsequent page.

    Takes a raw body and lowercases it, so callers cannot silently get
    case-sensitive matching wrong.
    """
    return _matches_radware_markers(body.lower())


class ChallengeType(enum.Enum):
    """WAF/challenge types that wafer can detect."""

    CLOUDFLARE = "cloudflare"
    AKAMAI = "akamai"
    DATADOME = "datadome"
    PERIMETERX = "perimeterx"
    IMPERVA = "imperva"
    KASADA = "kasada"
    SHAPE = "shape"
    RADWARE = "radware"
    AWSWAF = "awswaf"
    ACW = "acw"
    TMD = "tmd"
    AMAZON = "amazon"
    REDDIT = "reddit"
    VERCEL = "vercel"
    ARKOSE = "arkose"
    GEETEST = "geetest"
    HCAPTCHA = "hcaptcha"
    RECAPTCHA = "recaptcha"
    GENERIC_JS = "generic_js"
    CLOUDFLARE_BLOCK = "cloudflare_block"


# Terminal classifications: the WAF denied the request outright instead of
# issuing something to solve. Nothing wafer can vary — fingerprint, headers,
# a real browser — changes the answer, so these never reach the retry,
# rotation, or browser-solve paths; they are reported to the caller at once.
TERMINAL_CHALLENGES = frozenset({ChallengeType.CLOUDFLARE_BLOCK})


# Radware is deliberately absent from JS_ONLY_CHALLENGES below. Its
# interstitial hands over the clearance cookies itself, so replaying the
# request on the same jar clears it without running any JS. Listing it would
# invert that: with no browser configured, JS_ONLY raises ChallengeDetected
# immediately and the free replay never runs.
#
# Challenge types that require JS execution to solve. Fingerprint
# rotation alone cannot help — browser solver should be tried early.
# DataDome is included because its cookie is TLS+IP bound: when the
# TLS client gets 403, rotation to a different fingerprint from the
# same IP rarely helps, and each failed attempt poisons the IP for
# the subsequent browser solve.
JS_ONLY_CHALLENGES = frozenset({
    ChallengeType.AWSWAF,
    ChallengeType.CLOUDFLARE,
    ChallengeType.DATADOME,
    ChallengeType.KASADA,
    ChallengeType.TMD,
    ChallengeType.VERCEL,
    ChallengeType.HCAPTCHA,
    ChallengeType.RECAPTCHA,
    ChallengeType.GENERIC_JS,
})


def _has_cookie(set_cookie: str, name: str) -> bool:
    """Check if a Set-Cookie header sets a cookie with the given name.

    Looks for 'name=' to avoid matching cookie names that are
    substrings of other names (e.g., '_px3' in 'my_px3_token').
    """
    return f"{name}=" in set_cookie


def _header_fast_path(
    status_code: int, headers: dict[str, str], set_cookie: str
) -> ChallengeType | None:
    """Header-only detection — no body decode needed.

    Returns a ChallengeType if we can definitively identify the WAF from
    headers alone, otherwise None to fall through to body inspection.
    """
    # Radware — the origin's own 3xx into the vendor's challenge host. Reached
    # only when the caller disabled redirect following; otherwise wafer has
    # already followed this hop and sees the captcha page instead.
    if 300 <= status_code < 400 and is_radware_challenge_redirect(
        headers.get("location", "")
    ):
        return ChallengeType.RADWARE

    # Cloudflare explicit challenge header
    if headers.get("cf-mitigated") == "challenge":
        return ChallengeType.CLOUDFLARE

    # Vercel — x-vercel-mitigated: challenge header
    if headers.get("x-vercel-mitigated") == "challenge":
        return ChallengeType.VERCEL

    # Kasada — x-kpsdk-ct/x-kpsdk-cd headers on 403/429
    if status_code in (403, 429):
        for key in headers:
            if key.lower().startswith("x-kpsdk"):
                return ChallengeType.KASADA

    # AWS WAF — x-amzn-waf-action header (captcha/challenge)
    waf_action = headers.get("x-amzn-waf-action", "")
    if waf_action in ("captcha", "challenge"):
        return ChallengeType.AWSWAF

    # DataDome — datadome cookie + 403/429
    if status_code in (403, 429) and _has_cookie(set_cookie, "datadome"):
        return ChallengeType.DATADOME

    # PerimeterX — _px cookies + 403/429
    if status_code in (403, 429):
        if _has_cookie(set_cookie, "_px3") or _has_cookie(set_cookie, "_pxhd"):
            return ChallengeType.PERIMETERX

    # Imperva — reese84 or ___utmvc cookie + 403/429
    if status_code in (403, 429):
        if _has_cookie(set_cookie, "reese84") or _has_cookie(set_cookie, "___utmvc"):
            return ChallengeType.IMPERVA

    # Imperva — x-cdn header identifying Incapsula CDN on block status
    if status_code in (403, 429):
        x_cdn = headers.get("x-cdn", "").lower()
        if "incapsula" in x_cdn or "imperva" in x_cdn:
            return ChallengeType.IMPERVA

    # Akamai — _abck cookie + 403
    if status_code == 403:
        if _has_cookie(set_cookie, "_abck") or _has_cookie(set_cookie, "ak_bmsc"):
            return ChallengeType.AKAMAI

    # F5 Shape — sensor response headers on block status.
    #
    # INTENTIONAL HEURISTIC. Shape is server-side with no public header
    # schema (https://my.f5.com/manage/s/article/K000150733), so there is
    # no exact signature to key on. The site-specific sensor header is
    # ``x-<prefix>-a`` carrying an encoded/numeric token. The reliable
    # nordstrom path is the *body* marker (``istlWasHere``) checked later;
    # this header path is a fallback for a bare 403/429 with no body.
    #
    # Tightened (phase 8) to cut false positives: the old check accepted
    # any digit-leading value, so a trivial ``x-cache-a: 1`` /
    # ``x-served-a: 200`` (cache hints, ms timings, status echoes) tripped
    # it. We now require the value to actually *look* like a sensor token:
    # a minimum length AND a token character-class (no spaces / free text),
    # OR a long value. Real Shape tokens are long encoded blobs, so this
    # keeps recall while rejecting short numeric/word noise.
    if status_code in (403, 429):
        for key in headers:
            kl = key.lower()
            # Shape's sensor headers have site-specific prefixes (x-<prefix>-a)
            # but always include the -a suffix for the primary sensor.
            if kl.startswith("x-") and kl.endswith("-a") and len(kl) <= 20:
                val = headers[key]
                if _looks_like_shape_sensor(val):
                    return ChallengeType.SHAPE

    return None


# Token characters seen in Shape sensor response values (base64url / hex /
# numeric, with a few separators). Notably excludes spaces, so free-text
# values like "no-cache" attributes or "200 OK"-style echoes never match.
_SHAPE_TOKEN_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.=/+"
)
# Encoding separators that an ordinary English word would not contain. A
# moderate-length value carrying one of these is much more likely an
# encoded sensor blob than a plain word.
_SHAPE_SEPARATORS = frozenset("-_.=/+")
# Minimum length for the short-token path. Short values (status codes, ms
# timings, cache hit counts, single words) are common on x-*-a headers from
# CDNs and must not be mistaken for a Shape sensor token.
_SHAPE_MIN_TOKEN_LEN = 8


def _looks_like_shape_sensor(val: str) -> bool:
    """Heuristic: does ``val`` resemble an F5 Shape sensor response token?

    Conservative tightening of the old "digit-leading OR len>40" rule.
    The value must be entirely token characters (no spaces / free text),
    and then either:

    - long (>40 chars) — the typical encoded sensor blob, OR
    - at least ``_SHAPE_MIN_TOKEN_LEN`` chars AND looks encoded: either
      digit-leading (a numeric sensor token) or containing an encoding
      separator (``-_.=/+``), which a plain English word would not.

    This rejects short numeric echoes (``200``), single words (``blocked``,
    ``redirect``), and free text, while still matching numeric tokens and
    base64url blobs that may start with a letter.
    """
    if not val:
        return False
    if not all(c in _SHAPE_TOKEN_CHARS for c in val):
        return False
    if len(val) > 40:
        return True
    if len(val) < _SHAPE_MIN_TOKEN_LEN:
        return False
    return val[0].isdigit() or any(c in _SHAPE_SEPARATORS for c in val)


def detect_challenge(
    status_code: int, headers: dict[str, str], body: str
) -> ChallengeType | None:
    """Detect bot challenge type from HTTP response.

    Args:
        status_code: HTTP status code (int, not StatusCode object).
        headers: Response headers as {name: value} dict. Keys should be
            lowercase for consistent matching. Set-Cookie values may be
            semicolon-delimited or appear multiple times.
        body: Response body as decoded text.

    Returns:
        ChallengeType enum member, or None if no challenge detected.
    """
    set_cookie = headers.get("set-cookie", "")

    # Fast path: header-only detection (no body decode needed)
    result = _header_fast_path(status_code, headers, set_cookie)
    if result is not None:
        logger.info("Challenge detected (header): %s", result.value)
        return result

    # --- Inline-solvable challenges (cheapest first) ---

    # ACW (Alibaba Cloud WAF) — acw_sc__v2 marker in body
    if "acw_sc__v2" in body and "arg1" in body:
        logger.info("Challenge detected: acw")
        return ChallengeType.ACW

    # TMD (Alibaba) — punish page, status 200
    if status_code == 200 and "/_____tmd_____/punish" in body:
        logger.info("Challenge detected: tmd")
        return ChallengeType.TMD

    # Reddit anonymous-session gates. JSON endpoints return a large Shreddit
    # block template, while direct HTML navigation can return a small, valid
    # 200 verification form. The latter goes through the strict verification
    # parser so an ordinary successful Reddit page cannot become a bootstrap
    # loop.
    if (
        status_code == 403
        and "theme-beta" in body[:256].lower()
        and "you've been blocked by network security" in body.lower()
    ):
        logger.info("Challenge detected: reddit")
        return ChallengeType.REDDIT
    if (
        status_code == 200
        # Bounded prefix, like the 403 probe above: this runs on every
        # successful 200 that reaches here, and lowercasing a multi-megabyte
        # body to look for a <title> in <head> is pure waste.
        and "reddit - please wait for verification" in body[:4096].lower()
        and is_reddit_verification(body)
    ):
        logger.info("Challenge detected: reddit")
        return ChallengeType.REDDIT

    # Amazon rate-limit captcha — status 200, small body, "Continue shopping"
    if status_code == 200 and len(body) < 50_000:
        body_lower = body.lower()
        if "continue shopping" in body_lower:
            if (
                "amazon" in body_lower
                or "amzn" in body_lower
                or "/errors/validatecaptcha" in body_lower
            ):
                logger.info("Challenge detected: amazon")
                return ChallengeType.AMAZON

    # --- Browser-solvable challenges ---

    # Cloudflare — body markers (fallback without cf-mitigated header)
    # CF challenges come on 403 and 503 (older configs omit cf-mitigated).
    if status_code in (403, 503) and (
        "window._cf_chl_opt" in body
        or "_cf_chl_ctx" in body
        or "challenge-form" in body
    ):
        logger.info("Challenge detected (body): cloudflare")
        return ChallengeType.CLOUDFLARE

    # AWS WAF — aws-waf-token cookie + block status (202 = JS challenge)
    if _has_cookie(set_cookie, "aws-waf-token") and status_code in (
        202,
        403,
        405,
        429,
    ):
        logger.info("Challenge detected: awswaf")
        return ChallengeType.AWSWAF

    # AWS WAF — 202 with challenge body (gokuProps is the JS challenge SDK)
    if status_code == 202 and (
        "gokuProps" in body or "awsWafCookieDomainList" in body
    ):
        logger.info("Challenge detected (body): awswaf")
        return ChallengeType.AWSWAF

    # Akamai — _abck cookie + non-403 status with body markers
    if _has_cookie(set_cookie, "_abck") or _has_cookie(set_cookie, "ak_bmsc"):
        if status_code != 200 and (
            "bmSz" in body or "sensor_data" in body or "_BomA" in body
        ):
            logger.info("Challenge detected (body): akamai")
            return ChallengeType.AKAMAI
        # Akamai behavioral challenge — 200 with tiny challenge page
        if status_code == 200 and len(body) < 10_000:
            if "sec-if-cpt" in body or "behavioral-content" in body:
                logger.info("Challenge detected (body): akamai behavioral")
                return ChallengeType.AKAMAI

    # Compute body_lower once for all remaining case-insensitive checks
    body_lower = body.lower()

    # F5 Shape body markers — checked on any status code because Shape
    # returns 200 for interstitial challenge pages (nordstrom.com).
    if "istlwashere" in body_lower or "_imp_apg_r_" in body:
        logger.info("Challenge detected (body): shape")
        return ChallengeType.SHAPE

    # Radware Bot Manager — checked on any status code, and ahead of the
    # 403/429 block below so the generic-JS fallback can never swallow a
    # Radware block that arrives as 403. The measured gojobs.gov.on.ca
    # deployment serves it as a plain HTTP 200: the origin answers the first
    # request with a 302 that sets the __uzm* cookies, then redirects to
    # validate.perfdrive.com, which returns the captcha template as 200. To a
    # caller that is a clean, ordinary success — which is exactly why this
    # needs a body check rather than a status or header one.
    if _matches_radware_markers(body_lower):
        logger.info("Challenge detected (body): radware")
        return ChallengeType.RADWARE

    # Body-based detection for 403/429
    if status_code in (403, 429):

        # Cloudflare WAF *block* (Error 1020 and the 100x IP bans) — a
        # denial, not a challenge. Cloudflare serves its static error
        # stylesheet on every error page, while a real interstitial always
        # loads /cdn-cgi/challenge-platform/... to run the challenge. That
        # pair — error stylesheet present, challenge script absent — is what
        # separates "the request matched a rule" from "prove you're a
        # browser", and only the second one is solvable.
        if (
            status_code == 403
            and "/cdn-cgi/styles/cf.errors.css" in body_lower
            and "challenge-platform" not in body_lower
            and "cf_chl" not in body_lower
        ):
            logger.info("Challenge detected (body): cloudflare_block")
            return ChallengeType.CLOUDFLARE_BLOCK

        # Akamai body markers — bazadebezolkohpepadr is the obfuscated
        # global variable set by Akamai Bot Manager's sensor script.
        # Only match the sensor marker, not the company name (which
        # appears on CDN docs, privacy policies, and branded error pages).
        if status_code == 403 and "bazadebezolkohpepadr" in body_lower:
            logger.info("Challenge detected (body): akamai")
            return ChallengeType.AKAMAI

        # DataDome body markers
        if status_code in (403, 429) and (
            "datadome" in body_lower or "dd.js" in body_lower
        ):
            logger.info("Challenge detected (body): datadome")
            return ChallengeType.DATADOME

        # PerimeterX body markers (also 429 — DigiKey returns 429 with PX challenge)
        if (
            "perimeterx" in body_lower
            or "human.security" in body_lower
            or "press & hold" in body_lower
            or "px-captcha" in body_lower
        ):
            logger.info("Challenge detected (body): perimeterx")
            return ChallengeType.PERIMETERX

        # Imperva body markers
        if (
            "incapsula" in body_lower or "imperva" in body_lower
        ):
            logger.info("Challenge detected (body): imperva")
            return ChallengeType.IMPERVA

        # Kasada body markers
        # Modern Kasada uses p.js via double-UUID paths, legacy uses ips.js
        if "ips.js" in body_lower or "kpsdk" in body_lower or "/p.js" in body:
            logger.info("Challenge detected (body): kasada")
            return ChallengeType.KASADA

        # AWS WAF body markers
        if "aws-waf-token" in body_lower or (
            "awswafjschallenge" in body_lower
        ):
            logger.info("Challenge detected (body): awswaf")
            return ChallengeType.AWSWAF

        # Arkose Labs (FunCaptcha) body markers
        if "arkoselabs.com" in body_lower or "funcaptcha" in body_lower:
            logger.info("Challenge detected (body): arkose")
            return ChallengeType.ARKOSE

        # hCaptcha — checkbox/image CAPTCHA on login/gate pages
        if "hcaptcha.com" in body_lower or "h-captcha" in body_lower:
            logger.info("Challenge detected (body): hcaptcha")
            return ChallengeType.HCAPTCHA

        # reCAPTCHA — checkbox/invisible CAPTCHA
        if (
            "google.com/recaptcha" in body_lower
            or "g-recaptcha" in body_lower
        ):
            logger.info("Challenge detected (body): recaptcha")
            return ChallengeType.RECAPTCHA

        # Generic JS fallback — 403/429 with script tag + small body
        if "<script" in body_lower and len(body) < 50_000:
            logger.info("Challenge detected: generic_js")
            return ChallengeType.GENERIC_JS

    # Imperva interstitials — served as HTTP 200, detected by structural
    # markers, never by locale-dependent text. The _Incapsula_Resource
    # path is the Imperva resource loader, but it appears on BOTH the
    # interstitial AND real protected pages (which embed the reese84
    # sensor script via the same path). So the marker alone is not enough
    # — matching it on every page would cause false re-detection after a
    # solve. NOTE: the x-cdn header is likewise insufficient (real
    # Imperva-CDN pages carry it too). The interstitial is distinguished
    # from a real page by either of two body-only signals:
    #   1. a tiny body (<5KB) — the classic Incapsula "Request
    #      unsuccessful" block page, AND
    #   2. interstitial-only JS hooks from the modern reese "Pardon Our
    #      Interruption" template (e.g. realtor.ca, ~6.4KB). These hooks
    #      never appear on real content pages, so they hold at any size.
    if status_code == 200 and "_incapsula_resource" in body_lower:
        interstitial_markers = any(
            hook in body_lower for hook in IMPERVA_INTERSTITIAL_HOOKS
        )
        if len(body) < 5_000 or interstitial_markers:
            logger.info("Challenge detected (body): imperva interstitial")
            return ChallengeType.IMPERVA

    # Arkose Labs on 200 — embedded enforcement widget on login/signup pages
    if status_code == 200 and len(body) < 100_000:
        if "arkoselabs.com" in body or "funcaptcha" in body_lower:
            logger.info("Challenge detected (body): arkose")
            return ChallengeType.ARKOSE

    # GeeTest v4 — slide CAPTCHA on login/rate-limit pages.
    # Only trigger on small pages (<100KB) to avoid false positives on
    # normal pages that embed GeeTest as an optional form component.
    if status_code == 200 and len(body) < 100_000 and (
        "initGeetest4" in body
        or "gcaptcha4.geetest.com" in body
        or "gt4.js" in body
    ):
        logger.info("Challenge detected (body): geetest")
        return ChallengeType.GEETEST


    return None
