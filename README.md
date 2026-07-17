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
resp.content       # bytes -true wire body, decompressed but otherwise exact
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
resp.inline_solves  # int -inline challenge solves used (ACW, Amazon, TMD)
resp.challenge_type # str | None -WAF challenge type if detected
resp.emulation      # str | None -the identity that served this response, for
                    #   diagnosing a 403 (e.g. "Profile.Chrome149", "safari")
```

To read the session's *accumulated* cookie state (not just one response's
Set-Cookie headers), use `session.get_cookie(name, url)`:

```python
# Scoped to url's host: exact-host cookies first, then parent-domain cookies
# (Domain=.example.com matches www.example.com). Covers every transport the
# session uses. Secure cookies are only returned for https:// URLs. None if
# absent; never raises.
cf = session.get_cookie("cf_clearance", "https://example.com")
```

## Session Configuration

```python
import datetime
from wafer import SyncSession, AsyncSession

session = SyncSession(
    # TLS fingerprint (defaults to newest Chrome)
    emulation=None,  # or wreq.Emulation.Chrome149

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

    # Cookies (disk cache for solver cookies; recommended with BrowserSolver)
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
    rate_limit=1.0,      # seconds between requests per domain
    rate_jitter=0.5,     # random jitter added to interval

    # TLS rotation
    rotate_every=None,   # rebuild TLS session every N requests (None to disable)

    # Redirects
    follow_redirects=True,
    max_redirects=10,

    # Proxy
    proxy="socks5://user:pass@host:port",  # HTTP/HTTPS/SOCKS4/SOCKS5

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

`AsyncSession` accepts the same parameters. All are optional with sensible defaults.

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

Wafer uses wreq's `Emulation` profiles to produce browser-identical TLS fingerprints (JA3, JA4, HTTP/2 SETTINGS frames, header order). Defaults to the newest Chrome profile.

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
session = SyncSession(emulation=Emulation.Edge147)

# Firefox: Gecko TLS/H2, Firefox Accept and Accept-Language (...;q=0.5),
# and NO sec-ch-ua client hints at all (Firefox sends none).
session = SyncSession(emulation=Emulation.Firefox149)
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
wafer.emulation_family(Emulation.Edge147)     # "edge"
wafer.emulation_is_mobile(Emulation.SafariIos26_2)  # True
wafer.build_fingerprint_envelope(Emulation.Chrome149, user_agent="...")  # full dict
```

On a 403 or challenge, wafer automatically rotates across browser families (Chrome -> Firefox -> Safari -> Edge), swapping the header envelope to match each TLS fingerprint. This is far more effective than cycling between Chrome versions, which share one Chromium reputation pool. See [Retry and Rotation](#retry-and-rotation).

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

Safari is particularly effective against DataDome, which heavily fingerprints the TLS layer -Safari's profile is less commonly spoofed than Chrome's.

## Challenge Detection

Wafer detects 17 WAF challenge types from response status, headers, and body.
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
| Arkose / FunCaptcha | `arkoselabs.com` or `funcaptcha` markers | **detect-only** (no solver; the generic browser fallback can't pass FunCaptcha) |
| GeeTest v4 | `initGeetest4`, `gcaptcha4.geetest.com`, `gt4.js` | browser |
| hCaptcha | `hcaptcha.com` script, `h-captcha` div | browser |
| reCAPTCHA | `google.com/recaptcha` script, `g-recaptcha` div | browser for v2 (checkbox + grid); v3 score tokens are minted browser-free via [`session.mint_recaptcha_v3()`](#recaptcha-v3-token-minting) |
| Vercel | Vercel bot protection challenge | browser (generic JS wait) |
| Generic JS | Unclassified JavaScript challenges | browser (generic JS wait) |

When a challenge is detected, wafer escalates automatically:
1. Inline solving (ACW, Amazon, TMD - no browser needed)
2. For Imperva, a native OpenSSL transport that TLS-fingerprinting sites
   free-pass (no browser - see [Imperva bypass](#imperva--incapsula-no-browser-bypass))
3. Browser solver if configured (JS challenges: Cloudflare, DataDome, reCAPTCHA,
   and Imperva `reese84` under heavy load)
4. Chrome -> Safari fingerprint rotation
5. Raises `ChallengeDetected` if all attempts fail

## Inline Solvers

Three challenge types are solved without a browser:

- **ACW (Alibaba Cloud WAF)** -Extracts the obfuscated cookie value from the challenge page JavaScript, computes the XOR-shuffle, and sets the `acw_sc__v2` cookie.
- **Amazon CAPTCHA** -Parses the captcha form and submits it programmatically.
- **TMD (Alibaba TMD)** -Warms the session by fetching the homepage to establish a valid TMD session token.

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

Cookies are always enabled (in-memory jar). With `BrowserSolver`, enable disk persistence to avoid re-solving expensive WAF challenges across restarts:

```python
# Disk persistence for solver cookies (recommended with BrowserSolver)
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

Per-domain rate limiting with configurable intervals and jitter:

```python
session = SyncSession(
    rate_limit=2.0,    # at least 2s between requests per domain
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

WAF reputation pools key on browser *family*, so wafer escalates across families before cycling versions within one (Chrome145 -> 146 -> 147 all share a single Chromium pool -the weakest axis). Each family switch also swaps the HTTP header envelope (Accept, Accept-Language, sec-ch-ua) so the headers stay coherent with the new TLS fingerprint:

1. **Fresh TLS session** (rotation 1) -rebuilds the wreq client (new TLS session, empty cookie jar) on the *same* family. Often enough when the 403 is from a stale session or tainted cookies.
2. **Firefox** (rotation 2) -`Emulation.Firefox149`: Gecko TLS/H2, no sec-ch-ua.
3. **Safari** (rotation 3) -wafer's wire-verified Safari 26 (custom TlsOptions/Http2Options).
4. **Edge** (rotation 4) -`Emulation.Edge147`: Chromium TLS, "Microsoft Edge" brand.
5. **Chrome version cycling** (rotation 5+) -returns to Chrome and cycles versions.

The rung you reach is bounded by `max_rotations`: the **full** Chrome->Firefox->Safari->Edge ladder needs `max_rotations>=4` (Safari `>=3`, Edge `>=4`, version cycling `>=5`). The default `max_rotations=2` gives exactly one cross-family jump (fresh Chrome session, then Firefox) before wafer raises. The default is deliberately low -a higher budget burns more identities against the same host and worsens its reputation. A session started on a non-Chrome `emulation=` walks the same ladder, skipping its own starting family; `profile=` identities (Safari/Dart/Opera Mini) keep their own special-casing and are not forced into the ladder. A **pinned** fingerprint (after a browser solve) does not rotate.

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
    headless=False,       # headful for best stealth
    idle_timeout=300.0,   # close browser after 5min idle
    solve_timeout=30.0,   # max time per solve attempt; the call's timeout=
                          # (session default or per-request) caps it lower
)

# Use with a session -automatic fallback after rotation exhaustion
session = SyncSession(browser_solver=solver)
resp = session.get("https://protected-site.com")  # auto-solves challenges

# Or solve manually
result = solver.solve("https://protected-site.com", challenge_type="cloudflare")
if result:
    print(result.cookies)     # extracted cookies
    print(result.user_agent)  # browser's real UA
```

Uses [Patchright](https://github.com/Kaliiiiiiiiii-Vinyzu/patchright-python) (patched Playwright) with real system Chrome for maximum stealth. Persistent browser instance with idle timeout. Thread-safe.

Supports: Cloudflare (managed + Turnstile), Akamai, DataDome (WASM PoW auto-resolve + confirm click; bails out on interactive captchas -DD rejects CDP-dispatched input), PerimeterX (including press-and-hold), Imperva, Kasada, F5 Shape, AWS WAF, GeeTest v4 (slide puzzle), Alibaba Baxia (slider), hCaptcha (checkbox), reCAPTCHA v2 (checkbox + image grid via EfficientNet + D-FINE), and generic JS challenges.

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

Dev tool for recording human mouse movements and labeling reCAPTCHA training data. Recordings drive PerimeterX press-and-hold, drag/slide puzzle solvers (GeeTest, Baxia/AliExpress), reCAPTCHA grid tile clicking, and browse replay (background mouse/scroll activity during all solver wait loops). Seven recording modes: idle, path, hold, drag (puzzle), slide (full-width "slide to verify"), grid (short tile-to-tile hops for reCAPTCHA 3x3 grids), and browse. Two labeling modes: DET (annotate 4x4 detection grids with ground truth cells, auto-copies to CLS training data) and CLS (label individual 3x3 classification tiles into 16 object classes). See [`wafer/browser/mousse/README.md`](wafer/browser/mousse/README.md) for full documentation.

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
  _challenge.py     # Challenge detection (17 WAF types)
  _solvers.py       # Inline solvers (ACW, Amazon, TMD)
  _cookies.py       # JSON disk cache with TTL and LRU
  _fingerprint.py   # Emulation profiles, sec-ch-ua generation
  _profiles.py      # Profile enum (OPERA_MINI, SAFARI, DART)
  _opera_mini.py    # Opera Mini identity generation + stdlib HTTP transport
  _safari.py        # Safari 26 identity -TLS options, H2 options, headers
  _dart.py          # Dart 3.11 (Flutter) identity -TLS options, headers
  _native_tls.py    # Native OpenSSL transport (Imperva TLS-fingerprint bypass)
  _kasada.py        # Kasada CD (proof-of-work) generation
  _retry.py         # Retry strategy and backoff
  _ratelimit.py     # Per-domain rate limiting
  _errors.py        # Typed exceptions
  browser/
    __init__.py     # BrowserSolver, InterceptResult, format_cookie_str
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
