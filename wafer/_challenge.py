"""Challenge detection for 10+ WAF types.

Pure logic, no I/O. Inspects status code, headers, and body to identify
which WAF/challenge system is blocking a request.

Detection order is intentional:
1. Inline-solvable challenges first (ACW, TMD, Amazon) — cheapest to resolve
2. Browser-solvable challenges next (Cloudflare, Akamai, DataDome, etc.)
3. Generic JS fallback last
"""

import enum
import logging

logger = logging.getLogger("wafer")


class ChallengeType(enum.Enum):
    """WAF/challenge types that wafer can detect."""

    CLOUDFLARE = "cloudflare"
    AKAMAI = "akamai"
    DATADOME = "datadome"
    PERIMETERX = "perimeterx"
    IMPERVA = "imperva"
    KASADA = "kasada"
    SHAPE = "shape"
    AWSWAF = "awswaf"
    ACW = "acw"
    TMD = "tmd"
    AMAZON = "amazon"
    VERCEL = "vercel"
    ARKOSE = "arkose"
    GENERIC_JS = "generic_js"


# Challenge types that require JS execution to solve. Fingerprint
# rotation alone cannot help — browser solver should be tried early.
JS_ONLY_CHALLENGES = frozenset({
    ChallengeType.AWSWAF,
    ChallengeType.CLOUDFLARE,
    ChallengeType.KASADA,
    ChallengeType.VERCEL,
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
    # Cloudflare explicit challenge header
    if headers.get("cf-mitigated") == "challenge":
        return ChallengeType.CLOUDFLARE

    # Vercel — x-vercel-mitigated: challenge header
    if headers.get("x-vercel-mitigated") == "challenge":
        return ChallengeType.VERCEL

    # Kasada — x-kpsdk-ct header on 429
    if status_code == 429:
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

    # Imperva — reese84 or ___utmvc cookie + 403
    if status_code == 403:
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

    # F5 Shape — _imp_apg_r_ resource path in Set-Cookie or custom headers
    if status_code in (403, 429, 200):
        for key in headers:
            kl = key.lower()
            # Shape's sensor headers have site-specific prefixes (x-<prefix>-a)
            # but always include the -a suffix for the primary sensor
            if kl.startswith("x-") and kl.endswith("-a") and len(kl) <= 20:
                # Heuristic: short x-*-a headers are Shape sensor responses
                val = headers[key]
                # Shape response values are typically numeric or encoded
                if val and (val[0].isdigit() or len(val) > 40):
                    return ChallengeType.SHAPE

    return None


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

    # F5 Shape body markers — checked on any status code because Shape
    # returns 200 for interstitial challenge pages (nordstrom.com).
    if "istlwashere" in body.lower() or "_imp_apg_r_" in body:
        logger.info("Challenge detected (body): shape")
        return ChallengeType.SHAPE

    # Body-based detection for 403/429 (compute body_lower once)
    if status_code in (403, 429):
        body_lower = body.lower()

        # Akamai body markers — bazadebezolkohpepadr is the obfuscated
        # global variable set by Akamai Bot Manager's sensor script.
        if status_code == 403 and (
            "akam" in body_lower
            or "akamai" in body_lower
            or "bazadebezolkohpepadr" in body_lower
        ):
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
        if status_code == 403 and (
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

        # Generic JS fallback — 403/429 with script tag + small body
        if "<script" in body_lower and len(body) < 50_000:
            logger.info("Challenge detected: generic_js")
            return ChallengeType.GENERIC_JS

    # Imperva interstitials — served as 200 with tiny body (<5KB).
    # Detected by structural markers, never by locale-dependent text.
    # The _Incapsula_Resource script path is unique to Imperva challenge
    # pages and monitoring. Combined with a tiny body, it's definitive.
    # NOTE: x-cdn header alone is NOT sufficient — real Imperva-CDN
    # pages also have it, causing false re-detection after solve.
    if status_code == 200 and len(body) < 5_000:
        if "_incapsula_resource" in body.lower():
            logger.info("Challenge detected (body): imperva interstitial")
            return ChallengeType.IMPERVA

    # Arkose Labs on 200 — embedded enforcement widget on login/signup pages
    if status_code == 200 and len(body) < 100_000:
        if "arkoselabs.com" in body or "funcaptcha" in body.lower():
            logger.info("Challenge detected (body): arkose")
            return ChallengeType.ARKOSE

    return None
