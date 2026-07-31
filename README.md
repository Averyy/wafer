# wafer

> **Proof of concept.** This project is experimental and not intended for production use. Expect breaking changes, rough edges, and missing features.

Anti-detection HTTP client for Python. Built on [wreq](https://github.com/0x676e67/wreq-python) (Rust + BoringSSL).

Handles TLS fingerprinting, WAF challenge detection/solving, cookie caching, retry with backoff, rate limiting, embed mode for iframe/XHR impersonation, and proxy support.

```bash
pip install wafer-py
```

> **Upgrading from rnet?** wafer's underlying HTTP library was renamed from `rnet` to `wreq`. If upgrading, run `pip uninstall rnet` first, then reinstall wafer.

## Quick Start

```python
import wafer

# One-shot request
resp = wafer.get("https://example.com")
print(resp.status_code)  # 200
print(resp.text)          # HTML string
print(resp.json())        # parsed JSON
print(resp.content)       # raw bytes (for PDFs, images, etc.)

# Session (reuses TLS identity, cookies, fingerprint)
with wafer.SyncSession() as session:
    resp = session.get("https://example.com")
    resp.raise_for_status()

# Async
async with wafer.AsyncSession() as session:
    resp = await session.get("https://example.com")
```

## Response API

Every request returns a `WaferResponse` with a requests/httpx-compatible interface:

```python
resp = wafer.get("https://example.com")

resp.status_code   # int -HTTP status code
resp.ok            # bool -True if 200 <= status < 300
resp.text          # str -decoded body (lazy, charset-aware: Content-Type charset,
                   #       HTML <meta charset>, then UTF-8; never raises)
resp.content       # bytes -decompressed response body in its original encoding
                   #         (NOT a utf-8 re-encode of .text; safe for binary)
resp.headers       # dict[str, str] -lowercase keys
resp.url           # str -final URL after redirects
resp.history       # list of (status_code, url) named tuples -one per followed
                   #   redirect hop, in order; [] when not redirected
resp.cookies       # dict[str, str] -cookies set by THIS response (name -> value,
                   #   attributes dropped); per-response, not the session jar
resp.json()        # parsed JSON
resp.raise_for_status()  # raises WaferHTTPError if not ok
resp.get_all(key)  # list[str] -all values for a header (e.g. Set-Cookie)
resp.retry_after   # float | None -parsed Retry-After header (seconds)

# Metadata
resp.elapsed        # float -seconds from request to response
resp.was_retried    # bool -True if retries/rotations were used
resp.retries        # int -normal retries used (5xx, connection errors)
resp.rotations      # int -fingerprint rotations used (403/challenge)
resp.inline_solves  # int -inline challenge solves used (ACW, Amazon, TMD, Reddit)
resp.challenge_type # str | None -WAF challenge type if detected
resp.needs_render   # bool -body is HTML that ships script but under 1000 chars
                    #   of visible text, i.e. a client-rendered shell. A hint
                    #   for deciding to call session.render(url)
resp.emulation      # str | None -the identity that served this response, for
                    #   diagnosing a 403 (e.g. "Profile.Chrome149", "safari")
```

To read the session's *accumulated* cookie state (not just one response's
Set-Cookie headers), use `session.get_cookie(name, url)`:

```python
# Scoped to url by RFC 6265 rules. A Domain cookie (Set-Cookie carried
# Domain=.example.com) is returned for www.example.com; a host-only cookie
# (Set-Cookie omitted Domain) only on the exact host it was set on, so one set
# on www.example.com is not visible at api.example.com. Path must match too,
# and the longest matching path wins. Covers every transport the session uses.
# Secure cookies are only returned for https:// URLs. None if absent; never
# raises.
cf = session.get_cookie("cf_clearance", "https://example.com")

# Value-free jar inspection for diagnosing a protected flow (no cookie values):
scopes = session.cookie_scope_summary("https://example.com")
# -> [{"name": ..., "domain": ..., "path": ..., "secure": ...}, ...]
```

## Session Configuration

```python
import datetime
from wafer import AsyncSession, Profile, SyncSession
from wreq import Emulation

session = SyncSession(
    # TLS fingerprint (defaults to newest Chrome)
    emulation=None,  # or Emulation.Chrome149
    profile=None,    # or Profile.SAFARI / IOS_SAFARI / DART / OPERA_MINI
    safari_locale="us",  # "us" or "ca" for Safari profiles
    headers=None,    # optional complete replacement for DEFAULT_HEADERS

    # Timeouts (float seconds or timedelta)
    timeout=30,                                    # float/int seconds. The TOTAL
                                                   # budget for the whole call (all
                                                   # retries, rotations, backoff/
                                                   # rate-limit/Retry-After waits,
                                                   # browser solves), session or
                                                   # per-request. attempt_timeout=
                                                   # bounds each individual try.
    connect_timeout=datetime.timedelta(seconds=10),  # or timedelta
    attempt_timeout=None,  # default None (no per-attempt cap). Caps each individual
                           # attempt so retries/rotations can fire while a server
                           # hangs. Overridable per-request.

    # Retry behavior
    max_retries=3,       # retries on 5xx / connection errors / empty 200
    max_rotations=2,     # fingerprint rotations on 403/challenge (cross-family ladder)

    # Cookies (disk cache for browser/inline solver cookies)
    cache_dir=None,  # default: in-memory only; set a path to persist solver cookies

    # Session health
    max_failures=3,      # consecutive failures before session retirement (None to disable)

    # Response-size cap (memory safety)
    max_response_size=None,  # None = no cap. When set, a body over this many bytes
                             # raises ResponseTooLarge (Content-Length short-circuit
                             # before reading, else streamed early-abort). Applies to
                             # every transport. Overridable per-request.

    # Fingerprint pool (opt-in; rotate through a fixed list WITHOUT retiring)
    fingerprint_pool=None,   # list[wreq.Emulation] | None. Overrides the default
                             # ladder; per-identity backoff; max_failures ignored.

    # Rate limiting
    rate_limit=1.0,      # seconds between requests to the same hostname
    rate_jitter=0.5,     # random jitter added to interval

    # TLS rotation
    rotate_every=None,   # rebuild TLS session every N requests (None to disable)

    # Redirects
    follow_redirects=True,
    max_redirects=10,

    # Proxy
    proxy="socks5://user:pass@host:port",  # HTTP/HTTPS/SOCKS4/SOCKS5

    # DNS pinning for non-browser transports. Cannot be combined with proxy=.
    resolve=None,  # dict[str, list[str]] mapping hostnames to validated IPs

    # Embed mode (see below)
    embed="xhr",  # or "xhr-jquery" or "iframe"
    embed_origin="https://embedder.example.com",
    embed_referers=["https://embedder.example.com/page"],

    # Browser solver (see below)
    browser_solver=None,
    solve_origin=None,   # origin page the auto-solve navigates to mint the WAF
                         # token (for JSON/XHR APIs that can't be top-navigated)
)
```

`AsyncSession` accepts the same parameters. All are optional.

## HTTP Methods

Module-level convenience functions (create a one-shot session per call):

```python
wafer.get(url, **kwargs)
wafer.post(url, **kwargs)
wafer.put(url, **kwargs)
wafer.delete(url, **kwargs)
wafer.head(url, **kwargs)
wafer.options(url, **kwargs)
wafer.patch(url, **kwargs)
```

Session methods (reuse connection, cookies, fingerprint):

```python
session.get(url, **kwargs)
session.post(url, **kwargs)
session.request("PATCH", url, **kwargs)
# ... all standard HTTP methods (GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH, TRACE)
```

Per-request kwargs: `headers`, `params`, `json`, `form`, `body`, `multipart`, `timeout`, `attempt_timeout`, `max_response_size`.

## TLS Fingerprinting

Wafer uses wreq's `Emulation` profiles for TLS and HTTP/2 fingerprints
(including JA3, JA4, SETTINGS frames, and header order). It defaults to the
newest available Chrome profile.

```python
# Automatic -newest Chrome
session = SyncSession()

# Specific profile
from wreq import Emulation
session = SyncSession(emulation=Emulation.Chrome149)
```

The `sec-ch-ua` header is auto-generated to match the emulated Chrome version using the same GREASE algorithm as Chromium source.

### Non-Chrome family profiles (Firefox / Edge)

Pass any wreq `Emulation` and wafer applies the matching HTTP header envelope automatically -you do not set headers yourself. The family is derived from the emulation:

```python
from wreq import Emulation

# Edge: Chromium TLS, Chrome-like Accept, but sec-ch-ua brand "Microsoft Edge"
# (carrying Edge's own build number, distinct from the Chromium build).
session = SyncSession(emulation=Emulation.Edge148)

# Firefox: Gecko TLS/H2, Firefox Accept and Accept-Language (...;q=0.5),
# and NO sec-ch-ua client hints at all (Firefox sends none).
session = SyncSession(emulation=Emulation.Firefox151)
```

Selecting a non-Chrome `emulation` only sets a coherent starting identity; the same cross-family rotation ladder still applies (see [Retry and Rotation](#retry-and-rotation)).

### Mobile profiles

wreq exposes mobile Emulation identities; the mobile TLS shape and mobile UA come from wreq, and wafer applies the family envelope (no sec-ch-ua, family-correct `Accept`):

```python
session = SyncSession(emulation=Emulation.SafariIos26_2)    # iPhone Safari
session = SyncSession(emulation=Emulation.SafariIpad26_2)   # iPad Safari
session = SyncSession(emulation=Emulation.FirefoxAndroid135)  # Android Firefox
```

There is no mobile Chromium profile in wreq, so wafer never sends `sec-ch-ua-mobile: ?1`. `emulation_is_mobile(...)` (and `fingerprint_envelope()["is_mobile"]`) is the only mobility signal.

### Inspecting the identity

```python
# What this session currently serves with (UA + client hints, on the wire):
env = session.fingerprint_envelope()
# {"user_agent": ..., "family": "chrome"|"edge"|"firefox"|..., "emulation": ...,
#  "sec_ch_ua": ..., "full_version_list": ..., "is_mobile": False, ...}

# Module-level helpers (stable public surface -do NOT reach into wafer._fingerprint):
import wafer
from wreq import Emulation
wafer.sec_ch_ua(147)                          # '"Google Chrome";v="147", ...'
wafer.sec_ch_ua(147, brand="Microsoft Edge")  # Edge brand
wafer.full_version(147)                       # "147.0.7727.24"
wafer.chrome_full_version(Emulation.Chrome149)  # "149.0.7827.201"
wafer.emulation_family(Emulation.Edge148)     # "edge"
wafer.emulation_is_mobile(Emulation.SafariIos26_2)  # True
wafer.build_fingerprint_envelope(Emulation.Chrome149, user_agent="...")  # full dict
```

On a 403 or challenge, wafer rotates across browser families (Chrome ->
Firefox -> Safari -> Edge), swapping the header envelope to match each TLS
fingerprint before cycling Chrome versions. See
[Retry and Rotation](#retry-and-rotation).

## Opera Mini Profile

`Profile.OPERA_MINI` impersonates Opera Mini in Extreme/Mini data-saving mode. Bypasses wreq entirely -uses Python's stdlib `urllib` with system OpenSSL, producing a server-side proxy TLS fingerprint (OpenSSL, not BoringSSL). HTTP/1.1 only, no `Sec-Ch-Ua` or `Sec-Fetch-*` headers.

Because Opera Mini cannot execute JavaScript, **challenge detection, fingerprint rotation, retry logic, and browser solving are all disabled**. Rate limiting still applies. GET only (`ValueError` on other methods).

```python
from wafer import SyncSession, AsyncSession, Profile

with SyncSession(profile=Profile.OPERA_MINI) as session:
    resp = session.get("https://example.com")

async with AsyncSession(profile=Profile.OPERA_MINI) as session:
    resp = await session.get("https://example.com")
```

## Safari Profile

`Profile.SAFARI` impersonates Safari 26 on macOS (M3/M4 hardware). Uses wreq with custom `TlsOptions` and `Http2Options` instead of Chrome's `Emulation` profiles, producing a TLS+H2 fingerprint matching real Safari 26.2/26.3 M3/M4 exactly.

Safari gets all of wafer's features -challenge detection, cookie caching, retry, rate limiting, browser solving, and session rotation.

```python
from wafer import SyncSession, AsyncSession, Profile

with SyncSession(profile=Profile.SAFARI) as session:
    resp = session.get("https://example.com")

# Canadian English locale
with SyncSession(profile=Profile.SAFARI, safari_locale="ca") as session:
    resp = session.get("https://example.com")

async with AsyncSession(profile=Profile.SAFARI) as session:
    resp = await session.get("https://example.com")
```

Safari supplies a non-Chromium TLS/H2 and header identity for sites where
changing Chromium versions does not alter challenge behavior.

## iOS Safari Profile

`Profile.IOS_SAFARI` impersonates Safari 26.5.2 on a real iPhone. It uses a
dedicated, wire-verified mobile TLS and HTTP/2 identity rather than wreq's
built-in `SafariIos*` emulations.

```python
from wafer import SyncSession, AsyncSession, Profile

with SyncSession(profile=Profile.IOS_SAFARI) as session:
    resp = session.get("https://example.com")

# Canadian English locale
with SyncSession(
    profile=Profile.IOS_SAFARI,
    safari_locale="ca",
) as session:
    resp = session.get("https://example.com")

async with AsyncSession(profile=Profile.IOS_SAFARI) as session:
    resp = await session.get("https://example.com")
```

The profile reproduces JA3 `ecdf4f49dd59effc439639da29186671`, JA4
`t13d2013h2_a09f3c656075_7f0f34a4126d`, and HTTP/2 fingerprint
`2:0;3:100;4:2097152;9:1|10420225|0|m,s,a,p`. Its UA deliberately contains
both `CPU iPhone OS 18_7` and `Version/26.5.2`; those are the exact tokens
sent by the real browser, not a version-normalization error.

Browser solving is rejected for this profile because wafer's solver is desktop
Chromium; replaying cookies minted by it would make the mobile Safari identity
incoherent. The Imperva native-OpenSSL fallback is also disabled because it
would replace the captured mobile ClientHello. Challenge detection, retries,
cookies, redirects, proxies, rate limiting, and embed headers remain
available. See [docs/ref-ios.md](docs/ref-ios.md) for the measured fingerprint
and limitations.

## Challenge Detection

Wafer detects 19 WAF challenge types from response status, headers, and body.
**Detection is not the same as solving** - the "Solved by" column shows how each
type is actually handled: `inline` (over HTTP, no browser), `browser` (needs a
configured `browser_solver`), or `detect-only` (raises `ChallengeDetected`; no
solver - you must handle it yourself).

| WAF | Detection | Solved by |
|-----|-----------|-----------|
| Cloudflare | `cf-mitigated` header, managed challenge HTML | browser |
| Akamai | `_abck` cookie patterns, sensor script references | browser |
| DataDome | `datadome` cookie, challenge page markers | browser |
| PerimeterX / HUMAN | `_px` cookies, captcha div, press-and-hold | browser |
| Imperva / Incapsula | `reese84`/`___utmvc` cookie, `_Incapsula_Resource` script, 200 "Pardon Our Interruption" interstitial | inline (native-TLS) + browser under load |
| Kasada | `429` with Kasada script markers | browser |
| F5 Shape | `istlWasHere` interstitial page | browser |
| AWS WAF | `aws-waf-token` cookie, `AwsWafIntegration` script | browser |
| ACW (Alibaba) | `acw_sc__v2` challenge script | inline |
| TMD | TMD session validation pattern | inline (+ browser slider) |
| Amazon | CAPTCHA page with `amzn` markers | inline |
| Reddit | cold-session JSON block or 200 HTML verification | inline first; optional browser cookie recovery |
| Arkose / FunCaptcha | `arkoselabs.com` or `funcaptcha` markers | **detect-only** (no solver; the generic browser fallback can't pass FunCaptcha) |
| GeeTest v4 | `initGeetest4`, `gcaptcha4.geetest.com`, `gt4.js` | browser |
| hCaptcha | `hcaptcha.com` script, `h-captcha` div | browser |
| reCAPTCHA | `google.com/recaptcha` script, `g-recaptcha` div | browser for v2 (checkbox + grid); v3 score tokens are minted browser-free via [`session.mint_recaptcha_v3()`](#recaptcha-v3-token-minting) |
| Vercel | Vercel bot protection challenge | browser (generic JS wait) |
| Generic JS | Unclassified JavaScript challenges | browser (generic JS wait) |
| Cloudflare WAF block | Error 1020 / IP-ban page: `cf.errors.css` present, `challenge-platform` absent | **terminal** -raises `RequestBlocked` at once, no retry or rotation |

When a challenge is detected, wafer escalates automatically:
1. Inline solving/warm-up (ACW, Amazon, Reddit, and the first TMD warm-up)
2. For Imperva, a native OpenSSL transport that TLS-fingerprinting sites
   free-pass (no browser - see [Imperva bypass](#imperva--incapsula-no-browser-bypass))
3. Browser solver if configured (JS challenges: Cloudflare, DataDome, reCAPTCHA,
   and Imperva `reese84` under heavy load)
4. Cross-family fingerprint rotation: fresh current family -> Firefox -> Safari -> Edge
5. Raises `ChallengeDetected` if all attempts fail

A terminal block skips all of it. A Cloudflare WAF *block* page is a denial, not
a challenge: nothing is issued to solve, and no identity answers it differently.
Wafer raises `RequestBlocked` on the first response, spending no budget.

## Inline Solvers

Four challenge types have an inline path that does not require a browser.
Reddit can optionally fall back to the configured browser if its strict inline
bootstrap fails:

- **ACW (Alibaba Cloud WAF)** -Extracts the obfuscated cookie value from the challenge page JavaScript, computes the XOR-shuffle, and sets the `acw_sc__v2` cookie.
- **Amazon CAPTCHA** -Parses the captcha form and submits it programmatically.
- **TMD (Alibaba TMD)** -First warms the session by fetching the homepage.
  If the issued punishment flow persists, the configured browser handles its
  Baxia slider or reCAPTCHA. A new target-scoped `x5sec` is imported for the
  authoritative native-HTTP replay. If Chrome instead reaches a validated,
  challenge-free exact GET document without transferable clearance, wafer
  returns that browser response directly and does not claim later HTTP requests
  are unlocked. A rejected or still-challenged Baxia document is discarded.
  When the total request deadline can fund them, wafer tries up to three fresh
  browser contexts with distinct recorded drags and a fair share of the
  remaining time, reserving up to 15 seconds for HTTP replay.
- **Reddit** -On a cold-session JSON block or direct 200 HTML verification
  page, performs New Reddit's logged-out verification at
  `https://www.reddit.com/` in the same TLS session, then replays the original
  request. If that strict inline flow fails and `browser_solver` is configured,
  wafer navigates the browser to that fixed HTML root (never the JSON URL),
  requires authoritative Reddit cookies, imports them, and replays the original
  request through wreq before trying fingerprint rotation. A session-level
  `solve_origin` does not override Reddit's fixed solve page. With `cache_dir`,
  every durable cookie-setting leg is persisted for fresh processes. Explicit
  `old.reddit.com` URLs are fetched as requested, but Old Reddit is never
  selected automatically or used as a fallback.

These run automatically during the retry loop.

## reCAPTCHA v3 token minting

reCAPTCHA **v3** issues a *score* token rather than a checkbox/grid challenge.
wafer mints these tokens **browser-free** -no Patchright, no JS execution -via
the cross-origin anchor + reload flow against Google's endpoints, run under the
session's own TLS-emulated client (so the token rides a real browser
fingerprint):

```python
token = session.mint_recaptcha_v3(
    sitekey="6Lc...",                  # readable from the page
    action="login",                    # the action name
    origin="https://www.example.com",  # site origin the sitekey is bound to
)
# Submit `token` to the site exactly as a browser would (g-recaptcha-response
# form field, or a JSON body to the site's verify endpoint).
```

`v` (the api.js release hash) is auto-scraped and cached on the session;
`enterprise=True` switches to the Enterprise endpoints. Raises `TokenMintFailed`
if a token can't be extracted. Embed-mode sessions are handled automatically
(embed headers are suspended for the Google requests). This is distinct from the
browser-based **v2** checkbox/grid solver in the table above.

**Caveat:** minting always produces a token, but the *score* Google assigns
depends on request reputation (IP, TLS, cookies) -wafer mints the token, it
cannot guarantee the site's score threshold passes.

## Cookie Cache

Cookies are always enabled in memory. Set `cache_dir` to persist browser and
inline solver cookies across sessions:

```python
# Disk persistence for browser/inline solver cookies
session = SyncSession(cache_dir="./data/wafer/cookies")

# In-memory only (default)
session = SyncSession(cache_dir=None)
```

Features:
- Per-domain JSON files with thread-safe atomic writes
- TTL-based expiration (respects `Expires` / `Max-Age`)
- LRU eviction (max 50 entries per domain by default)
- Cookies from browser solving are automatically cached

## Rate Limiting

Per-hostname rate limiting with configurable intervals and jitter:

```python
session = SyncSession(
    rate_limit=2.0,    # at least 2s between requests to the same hostname
    rate_jitter=1.0,   # add 0-1s random jitter
)
```

Both sync and async sessions block/await until the rate limit allows the next request. The wait is capped by the call's total `timeout=`, so rate-limit spacing never holds a request past its deadline (the total budget wins; a too-tight `timeout` raises `WaferTimeout` rather than over-waiting).

## Retry and Rotation

Wafer uses separate counters for different failure modes:

- **Retries** (`max_retries=3`): For 5xx server errors, connection failures, and empty 200s. Exponential backoff.
- **Rotations** (`max_rotations=2`): For 403/challenge responses. Escalates across browser families before cycling versions (see the ladder below).

After `max_failures` consecutive failures on a domain, the session is retired (full identity reset). Set to `None` to disable.

### Cross-family rotation ladder

Wafer escalates across browser families before cycling versions within one.
Each family switch also swaps the HTTP header envelope (Accept,
Accept-Language, sec-ch-ua) so the headers stay coherent with the new TLS
fingerprint:

1. **Fresh TLS session** (rotation 1) -rebuilds the wreq client (new TLS session, empty cookie jar) on the *same* family. Often enough when the 403 is from a stale session or tainted cookies.
2. **Firefox** (rotation 2) -`Emulation.Firefox151`: Gecko TLS/H2, no sec-ch-ua.
3. **Safari** (rotation 3) -wafer's wire-verified Safari 26 (custom TlsOptions/Http2Options).
4. **Edge** (rotation 4) -`Emulation.Edge148`: Chromium TLS, "Microsoft Edge" brand.
5. **Chrome version cycling** (rotation 5+) -returns to Chrome and cycles versions.

The rung you reach is bounded by `max_rotations`: the **full**
Chrome->Firefox->Safari->Edge ladder needs `max_rotations>=4` (Safari `>=3`,
Edge `>=4`, version cycling `>=5`). The default `max_rotations=2` gives one
cross-family jump (fresh Chrome session, then Firefox) before wafer raises. A
higher budget tries more identities against the same host. A session started
on a non-Chrome `emulation=` walks the same ladder, skipping its own starting
family; `profile=` identities (Safari/iOS Safari/Dart/Opera Mini) keep their
own special-casing and are not forced into the ladder. A fingerprint pinned
after earning browser-bound challenge state does not rotate. Reddit browser
recovery and challenge-absent Cloudflare passthrough do not pin.

### Fingerprint pool

`fingerprint_pool=[...]` is an opt-in alternative to the ladder: a fixed list of `Emulation` identities to rotate through (cycling), with **per-identity backoff** and **no session retirement** (`max_failures` is ignored). A failing identity accrues a strike and rests longer before it is retried, while the others are tried. `max_rotations` still bounds rotations per request.

```python
from wreq import Emulation
session = SyncSession(
    fingerprint_pool=[Emulation.Chrome149, Emulation.Firefox151, Emulation.Edge148],
    max_rotations=6,  # bound how many pool steps one request may take
)
```

### Empty-200 as a rotation signal

A `200 OK` with an empty body from a host that *already* returned real content this session is treated as a soft block on the current identity, not a real empty resource. After same-identity retries are spent, wafer rotates to a fresh identity (within `max_rotations`) and retries before raising `EmptyResponse`. A first-request empty 200 (host never proven content-capable) is not rotated -it could legitimately be an empty endpoint.

### Exhaustion behavior

When all rotations are exhausted, wafer either raises or returns the response depending on the failure type:

| Failure | Default (`max_rotations > 0`) | Bulk (`max_rotations = 0`) |
|---------|-------------------------------|---------------------------|
| 403 + challenge detected | Raises `ChallengeDetected` | Returns response |
| 403 + no challenge | Returns response | Returns response |
| 429 | Raises `RateLimited` | Returns response |
| 5xx / empty 200 | Returns response | Returns response |
| Connection error | Raises `ConnectionFailed` | Raises `ConnectionFailed` |
| Server hang past total `timeout` | Raises `WaferTimeout` | Raises `WaferTimeout` |

Callers using default mode should catch `ChallengeDetected` and `RateLimited` in addition to checking `raise_for_status()`:

```python
try:
    resp = session.get("https://example.com")
    resp.raise_for_status()
except ChallengeDetected as e:
    ...  # e.challenge_type, e.url, e.status_code
except RateLimited as e:
    ...  # e.retry_after (seconds or None)
```

## Embed Mode

Impersonate requests that originate from an iframe or fetch() call inside another page. Useful for scraping embedded widgets, map tiles, and API endpoints that validate `Sec-Fetch-*`, `Origin`, or `Referer` headers.

### XHR Mode (fetch/CORS)

Emulates a modern `fetch()` call: `Sec-Fetch-Mode: cors`, `Sec-Fetch-Dest: empty`, `Accept: */*`, `Origin` from `embed_origin`, navigation headers stripped.

```python
session = SyncSession(
    embed="xhr",
    embed_origin="https://seaway-greatlakes.com",
    embed_referers=["https://seaway-greatlakes.com/marine_traffic/en/marineTraffic_stCatherine.html"],
)
resp = session.get("https://www.marinetraffic.com/getData/get_data_json_4/z:11/X:285/Y:374/station:0")
```

### jQuery XHR Mode (`embed="xhr-jquery"`)

Same as `"xhr"` (identical CORS `Sec-Fetch-*`, `Origin`, Referer, stripped navigation headers), plus the two markers a legacy jQuery `$.ajax` / `XMLHttpRequest` call sends:

- `X-Requested-With: XMLHttpRequest`
- `Accept: application/json, text/javascript, */*; q=0.01` (the jQuery Accept, instead of `"xhr"`'s `*/*`)

Use this instead of plain `"xhr"` when the endpoint is a classic jQuery/XHR backend that expects `X-Requested-With` -many older `/ajax`, `getData`, tile, and autocomplete endpoints reject requests without it. Use plain `"xhr"` for modern `fetch()` endpoints (no `X-Requested-With`). Both markers are set at the client level to avoid HTTP/2 header duplication.

```python
session = SyncSession(
    embed="xhr-jquery",
    embed_origin="https://example.com",
    embed_referers=["https://example.com/page"],
)
resp = session.get("https://example.com/ajax/autocomplete?q=foo")
```

### Iframe Mode (navigation)

```python
session = SyncSession(
    embed="iframe",
    embed_origin="https://seaway-greatlakes.com",
    embed_referers=["https://seaway-greatlakes.com/marine_traffic/en/marineTraffic_stCatherine.html"],
)
resp = session.get("https://www.marinetraffic.com/widget")
```

See [`docs/ref-sec-fetch.md`](docs/ref-sec-fetch.md) for exact header values set by each mode.

### When to Use Which

| Scenario | Mode |
|----------|------|
| Widget's API/data endpoints (JSON, tiles) | `xhr` |
| Initial iframe page load (HTML) | `iframe` |
| Target only checks Referer/Origin headers | Either -no browser needed |
| Target requires JS execution or challenge solving | Use iframe intercept (see below) |

## Browser Solving

For challenges that require real JavaScript execution (Cloudflare Turnstile, PerimeterX press-and-hold, etc.):

```bash
pip install wafer-py[browser]
```

```python
from wafer.browser import BrowserSolver

solver = BrowserSolver(
    headless=False,       # default; headless has lower solve coverage
    idle_timeout=300.0,   # close browser after 5min idle
    solve_timeout=30.0,   # max time per solve attempt; the call's timeout=
                          # (session default or per-request) caps it lower
    # proxy="http://user:pass@proxy.example:8080",  # optional manual use
    egress_guard_proxy=None,  # optional loopback SOCKS5 destination guard
    executable_path=None, # optional Chrome/Chromium executable override
)
# Non-blocking readiness signal for health checks. It becomes true after Chrome
# launches and clears immediately on disconnect, idle close, or explicit close.
assert solver.runtime_ready is False

# Use with a session -automatic solving inside the retry loop
session = SyncSession(browser_solver=solver)
resp = session.get("https://protected-site.com")  # auto-solves challenges

# Or solve manually
result = solver.solve("https://protected-site.com", challenge_type="cloudflare")

# Or render manually (what session.render() drives; arender() is the async form)
rendered = solver.render("https://spa.example.com/")
if result:
    print(result.cookies)     # extracted cookies
    print(result.user_agent)  # browser's real UA
    print(result.response)    # CapturedResponse | None
    print(result.challenge_absent)  # True only for validated CF absence
```

Uses [Patchright](https://github.com/Kaliiiiiiiiii-Vinyzu/patchright-python)
(patched Playwright) with the installed Chrome. Chrome can auto-update ahead
of wreq's newest emulation; version skew is logged and accepted. Solve paths
that earn browser-bound challenge state align the session's User-Agent/client
hints to the launched browser. Reddit recovery and challenge-absent Cloudflare
passthrough do not pin the session. The browser instance persists until its
idle timeout and solver operations are serialized. A solver passed to a
session remains caller-owned: call `solver.close()` when it is no longer
needed, or rely on `idle_timeout`; exiting the session does not close it.

For automatic solves, the session keeps 10% of the remaining request timeout
(up to five seconds) outside the browser so it can inject the earned cookies
and retry the protected HTTP request before the caller's total deadline.

Cloudflare can be transparent to the real browser even when the initial wreq
request was challenged. If no Cloudflare iframe appears, wafer validates the
actual Playwright main-document response and returns its status, headers, and
body plus individual `Set-Cookie` values. This pass-through is limited to a
non-empty 2xx HTML `GET` with no server redirect. It rejects known
challenge/block bodies, cross-site or path-changing client navigation,
embedder/`solve_origin` loads, attachments, and original non-GET methods.
Query/fragment-only history rewrites are allowed. Because Patchright returns a
decoded body, stale wire `Content-Encoding`, `Content-Length`, and
`Transfer-Encoding` headers are removed. This path merges browser cookies
without pinning the fingerprint or rebuilding the wreq client.

When a session has both `proxy=` and `browser_solver=`, wafer configures the
solver to the same proxy before Chrome launches. A preconfigured, mismatched
solver (or a custom solver that cannot expose/configure its proxy) is rejected
so a browser challenge cannot bypass the session proxy or mint IP-bound cookies
on a different egress.

Supports: Cloudflare (managed + Turnstile), Akamai, DataDome (WASM PoW
auto-resolve + confirm click; interactive captchas are not solved), PerimeterX
(including press-and-hold), Imperva, Kasada, F5 Shape, AWS WAF, GeeTest v4
(slide puzzle), Alibaba Baxia (slider), hCaptcha (checkbox), reCAPTCHA v2
(checkbox + image grid via EfficientNet + D-FINE), Reddit fixed-origin cookie
recovery, and generic JS challenges.

### Rendering a JavaScript-built page (`session.render`)

Some pages have no content to fetch. The server ships a shell -a `<div id="root">`
and a script bundle -and the text, nav, and job listings are written by the client.
No fingerprint recovers markup that was never in the bytes. `session.render()`
loads the URL in the browser solver, waits for rendering to settle, and returns
the finished document as an ordinary `WaferResponse`:

```python
resp = session.get("https://spa.example.com/careers")
if resp.needs_render:                       # HTML + script, almost no text
    resp = session.render("https://spa.example.com/careers")
print(resp.text)                            # the DOM after hydration
```

No transport request is made -the render replaces the fetch. For an HTML document
`resp.text` is the serialized DOM (`Content-Type: text/html; charset=utf-8`). A
non-HTML resource -JSON, XML, plain text, an image -comes back as the bytes the
server sent under its real `Content-Type`, since Chrome displays those inside a
generated viewer document and serializing that would return the wrapper instead of
the resource; `resp.json()` on a rendered API URL works normally. Status and headers
always describe the document the body came from, including after a client-side
redirect. The browser follows redirects regardless of `follow_redirects`, so
`resp.url` is the final URL and `resp.history` is empty. Cookies the page set are
merged into the session jar.

A session with no `browser_solver=` creates one on its first render and closes it
on exit; from then on that session can also browser-solve challenges on ordinary
requests -and the usual solver rule applies, so a per-request
`headers={"User-Agent": ...}` that does not match the launched browser raises
`ValueError`. A solver you passed in stays yours to close.

A render that lands on a WAF interstitial solves it in place with the same per-WAF
handlers the solve path uses, then re-captures the page -so render works on
protected sites, not just open ones. The earned cookies land in the session jar
and the session pins its replay identity to the solving browser, so the
clearance survives the next ordinary request. Verified on `miata.net`
(Cloudflare): plain TLS gets a 403 challenge, the render returns the real 200
page in ~7s, and the follow-up `session.get()` returns 200 with no challenge. If the document is still a challenge
after that, `ChallengeDetected` is raised rather than the interstitial being
returned as content.

Rendered challenge classification starts with the document's real status.
Blocking-status fallback detection is limited to structurally recognized
interstitials, so an ordinary 200 page that merely references a WAF-related
script name is not routed into the wrong solver.

### Solving on an origin page (`solve_origin`)

When the request URL is a **JSON/XHR API** that can't be top-navigated (a real browser never navigates to a raw-JSON endpoint -the page just renders the JSON, the WAF's challenge JS never runs, and the solve times out), point the auto-solve at the site's real origin page with `solve_origin=`:

```python
session = SyncSession(
    browser_solver=solver,
    solve_origin="https://www.example.com/",  # real page; mints the WAF token
)
resp = session.get("https://api.example.com/v1/data")  # JSON API
```

On a challenge, the browser navigates `solve_origin`, runs the challenge there, earns the (registrable-domain-scoped) cookies, and they replay to the API host on the retried TLS request. Applies to **all** challenge types (it generalizes the Imperva "Error 15" origin-page solve); an explicit `solve_origin` overrides Imperva's auto-derived origin. Where to earn the token is wafer's job; the per-site *value* of `solve_origin` (which page mints it) is yours to supply.

## Imperva / Incapsula (no-browser bypass)

Some Imperva deployments (e.g. `api2.realtor.ca`) fingerprint the **TLS stack
itself** and challenge every BoringSSL client - so wreq's Chrome/Safari/Edge
emulations are all challenged and rotating between them can't help. A generic
OpenSSL client that sends the minimal "API client" header set (no `Sec-Fetch-*`)
gets a free pass instead. wreq can't produce an OpenSSL fingerprint, so wafer
automatically falls back to a stdlib `http.client` transport over system OpenSSL
(curl-byte-identical) on Imperva detection, pinned per host. No browser, no
`[browser]` extra:

```python
session = wafer.AsyncSession()  # no browser_solver needed for light usage
resp = await session.get(
    "https://api2.realtor.ca/Location.svc/SubAreaSearch",
    params={"Area": "Ottawa", "ApplicationId": "1", "CultureId": "1",
            "Version": "7.0", "CurrentPage": "1"},
    headers={"Origin": "https://www.realtor.ca",
             "Referer": "https://www.realtor.ca/"},
)
data = resp.json()  # real JSON, no challenge
```

Under **heavy load** these sites revoke the free pass and demand the `reese84`
JS token from every client. With a `browser_solver` configured, wafer solves
`reese84` once in a real browser and reuses the token across the session
(exactly how a real browser behaves) - so bursts keep returning data; without
one, the heavy state raises `ChallengeDetected`. The classic `reese84` JS
interstitial on full pages (amadeus, hkbea, realtor.ca's main site) is
browser-solved as before. See [`docs/ref-imperva.md`](docs/ref-imperva.md).

The Imperva "solve on the origin page, not the API host" trick is now also
available as a general, WAF-agnostic session option: pass `solve_origin=` (the
site's real page) and the auto-solve navigates there for **any** challenge type,
not just Imperva. Use it when the request URL is a JSON/XHR API that can't be
top-navigated. An explicit `solve_origin` overrides Imperva's auto-derived
origin heuristic. See [Browser Solving](#browser-solving) and `llms.txt`.

## Iframe Intercept

For embedded content that requires real browser bootstrapping -when the iframe runs JavaScript to generate auth tokens, solve challenges, or set cookies before API calls work.

```python
from wafer.browser import BrowserSolver

solver = BrowserSolver()

# Navigate to the embedder page, capture traffic from the target domain
result = solver.intercept_iframe(
    embedder_url="https://seaway-greatlakes.com/marine_traffic/en/marineTraffic_stCatherine.html",
    target_domain="marinetraffic.com",
    timeout=30.0,
)

if result:
    result.cookies    # cookies set for marinetraffic.com (by JS, challenges, etc.)
    result.responses  # all HTTP responses from marinetraffic.com during load
    result.user_agent # browser's real User-Agent
```

How it works:
1. Navigates to the embedder page in real Chrome
2. Iframes load naturally -CSP, CORS, X-Frame-Options all pass (it's a real browser)
3. Playwright captures every HTTP response from the target domain across all frames
4. Cookies for the target domain are extracted from the browser context
5. Everything is returned in an `InterceptResult` for replay via wreq

## Mouse Recorder (Mousse)

Dev tool for recording human mouse movements and labeling reCAPTCHA training data. Recordings drive PerimeterX press-and-hold, drag/slide puzzle solvers (GeeTest, Baxia/AliExpress), reCAPTCHA grid tile clicking, and browse replay (background mouse/scroll activity during all solver wait loops). Seven recording modes: idle, path, hold, drag (puzzle), slide (full-width "slide to verify"), grid (short tile-to-tile hops for reCAPTCHA 3x3 grids), and browse. Slide takes are pace-checked at record time -a slide is a fast confident flick that overshoots the end (0.35-1.40s pressed phase), not a puzzle drag, and takes outside that envelope are discarded. Two labeling modes: DET (annotate 4x4 detection grids with ground truth cells, auto-copies to CLS training data) and CLS (label individual 3x3 classification tiles into 16 object classes). See [`wafer/browser/mousse/README.md`](wafer/browser/mousse/README.md) for full documentation.

```bash
uv run python -m wafer.browser.mousse
```

## Errors

All exceptions inherit from `WaferError`:

```python
from wafer import (
    WaferError,          # base
    WaferTimeout,        # request exceeded timeout (also a TimeoutError)
    ChallengeDetected,   # WAF challenge unsolvable
    RequestBlocked,      # WAF rule denied the request (subclass of ChallengeDetected)
    RateLimited,         # HTTP 429
    ConnectionFailed,    # network error
    EmptyResponse,       # 200 with empty body
    TooManyRedirects,    # redirect loop
    ResponseTooLarge,    # body exceeded max_response_size cap
    TokenMintFailed,     # mint_recaptcha_v3() could not extract a token
    WaferHTTPError,      # raise_for_status() on non-2xx
)

try:
    resp = session.get("https://protected-site.com")
except ChallengeDetected as e:
    print(e.challenge_type)  # "cloudflare"
    print(e.url)
    print(e.status_code)
    print(e.response)        # final WaferResponse (body/headers), or None
except WaferTimeout as e:
    print(e.timeout_secs)    # deadline exceeded
except RateLimited as e:
    print(e.retry_after)     # seconds, or None
    print(e.response)        # final 429 WaferResponse, or None
except ResponseTooLarge as e:
    print(e.size, e.limit)   # bytes seen when the cap hit, and the cap
```

`ChallengeDetected`, `RateLimited`, and `EmptyResponse` carry the final blocked
`WaferResponse` as `e.response` (body, headers, status) -read
`e.response.text` instead of string-matching `str(e)`. It can be `None` in edge
cases where no response was in hand, so check before dereferencing. (Caution:
`e.response` may be a full WAF challenge page with embedded tokens -do not log it
unscrubbed.) `TokenMintFailed` carries `.stage` (`"anchor"`/`"reload"`/`"apijs"`)
and `.status_code`; see [reCAPTCHA v3 token minting](#recaptcha-v3-token-minting).

`RequestBlocked` subclasses `ChallengeDetected`, so existing handlers still
catch it. Catch it separately to tell "try again later" from "this will never
work as-is": a challenge can be solved, a block cannot, and only changing the
request itself (path, origin, egress address) changes the answer. Its
`.challenge_type` is `"cloudflare_block"`, which is also what
`resp.challenge_type` carries when `max_rotations=0` returns the block instead
of raising.

`ConnectionFailed.reason` names a sinkholed DNS answer when that is the cause -
a host that resolves only to `0.0.0.0` / `::` was refused by the resolver, not
unreachable. Pin the address with `resolve={"host": ["1.2.3.4"]}` or use another
resolver.

`WaferTimeout` inherits from both `WaferError` and `TimeoutError`, so `except WaferError` catches everything including timeouts.

## Logging

Silent by default. Enable via standard logging:

```python
import logging
logging.getLogger("wafer").setLevel(logging.DEBUG)
```

Logs retry attempts, fingerprint rotations, challenge detection, cookie cache operations, rate limit delays, browser solver activity, and embed mode header details.

## Architecture

```
wafer/
  __init__.py       # SyncSession, AsyncSession, module-level get/post/etc
  _base.py          # BaseSession -shared config and logic, zero I/O
  _sync.py          # SyncSession -wraps wreq.blocking.Client
  _async.py         # AsyncSession -wraps wreq.Client
  _response.py      # WaferResponse wrapper
  _challenge.py     # Challenge detection (18 WAF types)
  _solvers.py       # Inline solvers (ACW, Amazon, TMD, Reddit)
  _cookies.py       # JSON disk cache with TTL and LRU
  _fingerprint.py   # Emulation profiles, sec-ch-ua generation
  _profiles.py      # Profile enum (OPERA_MINI, SAFARI, IOS_SAFARI, DART)
  _opera_mini.py    # Opera Mini identity generation + stdlib HTTP transport
  _safari.py        # Safari 26 identity -TLS options, H2 options, headers
  _ios.py           # iOS Safari 26.5.2 identity -mobile TLS, H2, headers
  _dart.py          # Dart 3.11 (Flutter) identity -TLS options, headers
  _native_tls.py    # Native OpenSSL transport (Imperva TLS-fingerprint bypass)
  _kasada.py        # Kasada CD (proof-of-work) generation
  _retry.py         # Retry strategy and backoff
  _ratelimit.py     # Per-hostname rate limiting
  _errors.py        # Typed exceptions
  browser/
    __init__.py     # BrowserSolver, SolveResult, CapturedResponse, InterceptResult
    _solver.py      # Core BrowserSolver + mouse replay
    _cloudflare.py  # Cloudflare challenge solver
    _akamai.py      # Akamai challenge solver
    _datadome.py    # DataDome challenge solver
    _perimeterx.py  # PerimeterX press-and-hold solver
    _imperva.py     # Imperva/Incapsula challenge solver
    _kasada.py      # Kasada challenge solver
    _shape.py       # F5 Shape challenge solver
    _awswaf.py      # AWS WAF challenge solver
    _hcaptcha.py    # hCaptcha checkbox solver
    _recaptcha.py   # reCAPTCHA v2 checkbox + image grid dispatch
    _recaptcha_grid.py  # reCAPTCHA v2 image grid solver (EfficientNet + D-FINE)
    _drag.py        # GeeTest / Baxia drag/slider puzzle solver
    _cv.py          # CV notch detection for drag/slider puzzles
```

## LLM Integration

For LLMs (Claude Code, Copilot, etc.) writing code that uses wafer, see [`llms.txt`](llms.txt) for the complete API reference with exact types, defaults, constraints, and common mistakes.

## Development

```bash
uv venv && uv pip install -e ".[dev]"
uv run pytest tests/ -x -q
uv run ruff check wafer/ tests/
```

## License

Apache 2.0
