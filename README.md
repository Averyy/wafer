# wafer

Anti-detection HTTP client for Python. Built on [rnet](https://github.com/0x676e67/rnet) (Rust + BoringSSL).

Handles TLS fingerprinting, WAF challenge detection/solving, cookie caching, retry with backoff, rate limiting, embed mode for iframe/XHR impersonation, and proxy support.

```bash
pip install wafer-py
```

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

resp.status_code   # int — HTTP status code
resp.ok            # bool — True if 200 <= status < 300
resp.text          # str — decoded body (lazy, UTF-8 with replacement)
resp.content       # bytes — raw body (preserved exactly for binary)
resp.headers       # dict[str, str] — lowercase keys
resp.url           # str — final URL after redirects
resp.json()        # parsed JSON
resp.raise_for_status()  # raises WaferHTTPError if not ok
resp.get_all(key)  # list[str] — all values for a header (e.g. Set-Cookie)
resp.retry_after   # float | None — parsed Retry-After header (seconds)

# Metadata
resp.elapsed        # float — seconds from request to response
resp.was_retried    # bool — True if retries/rotations were used
resp.challenge_type # str | None — WAF challenge type if detected
```

Binary responses (images, PDFs, etc.) are detected automatically via Content-Type. `resp.content` preserves raw bytes exactly; `resp.text` decodes with replacement characters.

## Session Configuration

```python
import datetime
from wafer import SyncSession, AsyncSession

session = SyncSession(
    # TLS fingerprint (defaults to newest Chrome)
    emulation=None,  # or rnet.Emulation.Chrome145

    # Timeouts (float seconds or timedelta)
    timeout=30,                                    # float/int seconds
    connect_timeout=datetime.timedelta(seconds=10),  # or timedelta

    # Retry behavior
    max_retries=3,       # retries on 5xx / connection errors
    max_rotations=10,    # fingerprint rotations on 403/challenge

    # Cookies
    cache_dir="./data/wafer/cookies",  # disk persistence (default; None to disable)

    # Session health
    max_failures=3,      # consecutive failures before session retirement (None to disable)

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
    embed="xhr",  # or "iframe"
    embed_origin="https://embedder.example.com",
    embed_referers=["https://embedder.example.com/page"],

    # Browser solver (see below)
    browser_solver=None,
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

All `**kwargs` are passed through to rnet. Common per-request options:

```python
import datetime

# Custom headers (merged with session defaults; see wafer.DEFAULT_HEADERS)
resp = session.get(url, headers={"X-Custom": "value"})

# Per-request timeout (overrides session-level timeout)
resp = session.get(url, timeout=datetime.timedelta(seconds=5))

# Query parameters
resp = session.get(url, params={"q": "search", "page": "1"})

# Request body
resp = session.post(url, json={"key": "value"})
resp = session.post(url, form={"user": "alice", "pass": "secret"})  # URL-encoded
resp = session.post(url, data=b"raw bytes")
resp = session.post(url, content="string body")
```

## TLS Fingerprinting

Wafer uses rnet's `Emulation` profiles to produce browser-identical TLS fingerprints (JA3, JA4, HTTP/2 SETTINGS frames, header order). Defaults to the newest Chrome profile.

```python
# Automatic — newest Chrome
session = SyncSession()

# Specific profile
from rnet import Emulation
session = SyncSession(emulation=Emulation.Chrome145)
```

The `sec-ch-ua` header is auto-generated to match the emulated Chrome version using the same GREASE algorithm as Chromium source.

On repeated 403s, wafer automatically rotates to a different Chrome profile (different TLS fingerprint) and retries. After browser solving, the fingerprint is matched to the browser's real Chrome version.

## Opera Mini Profile

`Profile.OPERA_MINI` impersonates Opera Mini in Extreme/Mini data-saving mode. Real Opera Mini is a proxy browser: Opera's servers fetch pages, render them server-side with the Presto engine (frozen since 2015), and send compressed output to the phone. It is a pure HTTP/1.1 client with no JavaScript capability.

This profile **bypasses rnet entirely** and uses Python's stdlib `urllib` with system OpenSSL for HTTP transport. This avoids Chrome-specific header leakage (no `Sec-Ch-Ua`, no `Sec-Fetch-*`) and produces a TLS fingerprint consistent with a server-side proxy (OpenSSL), not a browser (BoringSSL).

Because Opera Mini cannot execute JavaScript, **challenge detection, fingerprint rotation, retry logic, and browser solving are all disabled** when this profile is active. Rate limiting still applies.

Headers are realistic Opera Mini Extreme mode headers: Presto User-Agent string, `X-OperaMini-Features`, `X-OperaMini-Phone`, `X-OperaMini-Phone-UA`, `Device-Stock-UA`, and Opera Mini's distinct `Accept-Encoding` order. All version data (client versions, server/transcoder versions, device models) comes from confirmed real-world captures, not algorithmic guessing. A new randomized identity (device, locale, feature set) is bound per session.

```python
from wafer import SyncSession, AsyncSession, Profile

# Sync
with SyncSession(profile=Profile.OPERA_MINI) as session:
    resp = session.get("https://example.com")
    print(resp.status_code)
    print(resp.text)

# Async
async with AsyncSession(profile=Profile.OPERA_MINI) as session:
    resp = await session.get("https://example.com")
```

| Feature | Chrome (default) | Opera Mini |
|---|---|---|
| HTTP transport | rnet (Rust + BoringSSL) | stdlib urllib (system OpenSSL) |
| HTTP version | HTTP/2 | HTTP/1.1 only |
| TLS fingerprint | Chrome Emulation | System OpenSSL (server-like) |
| User-Agent | Chrome | Opera Mini Presto proxy |
| sec-ch-ua / Sec-Fetch-* | Generated | Not sent |
| Challenge detection | All 14 WAF types | Disabled |
| Fingerprint rotation | Cycles Chrome versions | Disabled |
| Browser solving | Supported | Not available |
| Rate limiting | Per-domain | Per-domain (same) |
| Retry on 5xx | Yes | No (bypasses retry loop) |
| HTTP methods | All (GET, POST, PUT, etc.) | GET only (`ValueError` on others) |
| `add_cookie()` | Supported | Not supported (`NotImplementedError`) |

## Challenge Detection

Wafer detects 14 WAF challenge types from response status, headers, and body:

| WAF | Detection |
|-----|-----------|
| Cloudflare | `cf-mitigated` header, managed challenge HTML |
| Akamai | `_abck` cookie patterns, sensor script references |
| DataDome | `datadome` cookie, challenge page markers |
| PerimeterX / HUMAN | `_px` cookies, captcha div, press-and-hold |
| Imperva / Incapsula | `___utmvc` cookie, Reese84 script |
| Kasada | `429` with Kasada script markers |
| F5 Shape | `istlWasHere` interstitial page |
| AWS WAF | `aws-waf-token` cookie, `AwsWafIntegration` script |
| ACW (Alibaba) | `acw_sc__v2` challenge script |
| TMD | TMD session validation pattern |
| Amazon | CAPTCHA page with `amzn` markers |
| Arkose / FunCaptcha | `arkoselabs.com` or `funcaptcha` markers |
| Vercel | Vercel bot protection challenge |
| Generic JS | Unclassified JavaScript challenges |

When a challenge is detected, wafer:
1. Tries inline solving (ACW, Amazon, TMD — no browser needed)
2. Rotates TLS fingerprint and retries
3. Falls back to browser solver if configured
4. Raises `ChallengeDetected` if all attempts fail

## Inline Solvers

Three challenge types are solved without a browser:

- **ACW (Alibaba Cloud WAF)** — Extracts the obfuscated cookie value from the challenge page JavaScript, computes the XOR-shuffle, and sets the `acw_sc__v2` cookie.
- **Amazon CAPTCHA** — Parses the captcha form and submits it programmatically.
- **TMD (Alibaba TMD)** — Warms the session by fetching the homepage to establish a valid TMD session token.

These run automatically during the retry loop.

## Cookie Cache

Cookies are always enabled (in-memory jar) and optionally persisted to disk as JSON with TTL tracking and LRU eviction:

```python
# Disk persistence enabled (default: ./data/wafer/cookies)
session = SyncSession(cache_dir="./data/wafer/cookies")

# Disable disk persistence (in-memory only)
session = SyncSession(cache_dir=None)
```

Features:
- Per-domain JSON files with file locking for thread safety
- TTL-based expiration (respects `Expires` / `Max-Age`)
- LRU eviction (max 50 entries per domain by default)
- Cookies from browser solving are automatically cached
- Cached cookies are hydrated into the rnet cookie jar on session creation
- `session.add_cookie(raw_set_cookie, url)` injects a `Set-Cookie` value into the jar (e.g., from browser solving replay)

## Rate Limiting

Per-domain rate limiting with configurable intervals and jitter:

```python
session = SyncSession(
    rate_limit=2.0,    # at least 2s between requests per domain
    rate_jitter=1.0,   # add 0-1s random jitter
)
```

Both sync and async sessions block/await until the rate limit allows the next request.

## Retry and Rotation

Wafer uses separate counters for different failure modes:

- **Retries** (`max_retries=3`): For 5xx server errors and connection failures. Exponential backoff.
- **Rotations** (`max_rotations=10`): For 403/challenge responses. Rotates to a different Chrome TLS fingerprint and retries.

After `max_failures` consecutive failures on a domain, the session is retired (full identity reset). Set to `None` to disable.

## Redirect Following

```python
session = SyncSession(
    follow_redirects=True,  # default
    max_redirects=10,       # default
)
```

Handles 301, 302, 303, 307, 308 with correct method/body semantics. `resp.url` reflects the final URL after all redirects.

## Proxy Support

```python
# HTTP/HTTPS proxy
session = SyncSession(proxy="http://user:pass@proxy.example.com:8080")

# SOCKS5 proxy
session = SyncSession(proxy="socks5://user:pass@proxy.example.com:1080")
```

Supports HTTP, HTTPS, SOCKS4, and SOCKS5 with optional authentication.

## Embed Mode

Impersonate requests that originate from an iframe or fetch() call inside another page. Useful for scraping embedded widgets, map tiles, and API endpoints that validate `Sec-Fetch-*`, `Origin`, or `Referer` headers.

### XHR Mode (fetch/CORS)

```python
session = SyncSession(
    embed="xhr",
    embed_origin="https://seaway-greatlakes.com",
    embed_referers=["https://seaway-greatlakes.com/marine_traffic/en/marineTraffic_stCatherine.html"],
)
resp = session.get("https://www.marinetraffic.com/getData/get_data_json_4/z:11/X:285/Y:374/station:0")
```

Sets: `Sec-Fetch-Mode: cors`, `Sec-Fetch-Dest: empty`, `Origin`, `Accept: */*`. Referer sends the full URL from `embed_referers` (matching `strict-origin-when-cross-origin` for same-protocol requests). No `X-Requested-With` — add it per-request for jQuery-style XHR: `headers={"X-Requested-With": "XMLHttpRequest"}`.

### Iframe Mode (navigation)

```python
session = SyncSession(
    embed="iframe",
    embed_origin="https://seaway-greatlakes.com",
    embed_referers=["https://seaway-greatlakes.com/marine_traffic/en/marineTraffic_stCatherine.html"],
)
resp = session.get("https://www.marinetraffic.com/widget")
```

Sets: `Sec-Fetch-Mode: navigate`, `Sec-Fetch-Dest: iframe`, `Sec-Fetch-Site: cross-site`. No `Origin` (GET navigations don't send it). Keeps navigation `Accept` and `Upgrade-Insecure-Requests`.

### When to Use Which

| Scenario | Mode |
|----------|------|
| Widget's API/data endpoints (JSON, tiles) | `xhr` |
| Initial iframe page load (HTML) | `iframe` |
| Target only checks Referer/Origin headers | Either — no browser needed |
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
    solve_timeout=30.0,   # max time per solve attempt
)

# Use with a session — automatic fallback after rotation exhaustion
session = SyncSession(browser_solver=solver)
resp = session.get("https://protected-site.com")  # auto-solves challenges

# Or solve manually
result = solver.solve("https://protected-site.com", challenge_type="cloudflare")
if result:
    print(result.cookies)     # extracted cookies
    print(result.user_agent)  # browser's real UA
```

Uses [Patchright](https://github.com/AieatAssignment/Patchright) (patched Playwright) with real system Chrome for maximum stealth. Persistent browser instance with idle timeout. Thread-safe.

Supports: Cloudflare (managed + Turnstile), Akamai, DataDome, PerimeterX (including press-and-hold), Imperva, Kasada, F5 Shape, AWS WAF, and generic JS challenges.

## Iframe Intercept

For embedded content that requires real browser bootstrapping — when the iframe runs JavaScript to generate auth tokens, solve challenges, or set cookies before API calls work.

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
2. Iframes load naturally — CSP, CORS, X-Frame-Options all pass (it's a real browser)
3. Playwright captures every HTTP response from the target domain across all frames
4. Cookies for the target domain are extracted from the browser context
5. Everything is returned in an `InterceptResult` for replay via rnet

### Two-Layer Architecture

Iframe intercept and embed mode complement each other:

- **Iframe intercept** bootstraps the session (slow, once) — real browser, real JS execution, captures cookies/tokens
- **Embed mode** replays at scale (fast, many times) — rnet with correct headers and extracted cookies

```python
import wafer
from wafer.browser import BrowserSolver, format_cookie_str

# Phase 1: Bootstrap
solver = BrowserSolver()
result = solver.intercept_iframe(
    embedder_url="https://embedder.example.com/dashboard",
    target_domain="api.target.com",
)

# Phase 2: Replay
session = wafer.SyncSession(
    embed="xhr",
    embed_origin="https://embedder.example.com",
)
for cookie in result.cookies:
    cookie_str = format_cookie_str(cookie)
    session.add_cookie(cookie_str, "https://api.target.com")

resp = session.get("https://api.target.com/data")
```

## Mouse Recorder (Mousse)

Dev tool for recording human mouse movements used by the browser solver. Recordings drive PerimeterX press-and-hold, drag/slide puzzle solvers (GeeTest, Baxia/AliExpress), and browse replay (background mouse/scroll activity during all solver wait loops). Six recording modes: idle, path, hold, drag (puzzle), slide (full-width "slide to verify"), and browse. See [`wafer/browser/mousse/README.md`](wafer/browser/mousse/README.md) for full documentation.

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
    SessionBlocked,      # too many consecutive failures
    ConnectionFailed,    # network error
    EmptyResponse,       # 200 with empty body
    TooManyRedirects,    # redirect loop
    WaferHTTPError,      # raise_for_status() on non-2xx
)

try:
    resp = session.get("https://protected-site.com")
except ChallengeDetected as e:
    print(e.challenge_type)  # "cloudflare"
    print(e.url)
    print(e.status_code)
except WaferTimeout as e:
    print(e.timeout_secs)    # deadline exceeded
except RateLimited as e:
    print(e.retry_after)     # seconds, or None
```

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
  _base.py          # BaseSession — shared config and logic, zero I/O
  _sync.py          # SyncSession — wraps rnet.blocking.Client
  _async.py         # AsyncSession — wraps rnet.Client
  _response.py      # WaferResponse wrapper
  _challenge.py     # Challenge detection (14 WAF types)
  _solvers.py       # Inline solvers (ACW, Amazon, TMD)
  _cookies.py       # JSON disk cache with TTL and LRU
  _fingerprint.py   # Emulation profiles, sec-ch-ua generation
  _profiles.py      # Profile enum (OPERA_MINI, etc.)
  _opera_mini.py    # Opera Mini identity generation + stdlib HTTP transport
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
    _cv.py          # CV notch detection for drag/slider puzzles
```

## Development

```bash
uv venv && uv pip install -e ".[dev]"
uv run pytest tests/ -x -q
uv run ruff check wafer/ tests/
```

## Sec-Fetch Reference

### Exact Headers by Request Type (Chrome)

| Scenario | Sec-Fetch-Dest | Sec-Fetch-Mode | Sec-Fetch-Site | Sec-Fetch-User | Origin | X-Requested-With |
|---|---|---|---|---|---|---|
| Address bar / bookmark | `document` | `navigate` | `none` | `?1` | absent | absent |
| Same-origin link click | `document` | `navigate` | `same-origin` | `?1` | absent | absent |
| Cross-site link click | `document` | `navigate` | `cross-site` | `?1` | absent | absent |
| iframe (cross-origin) | `iframe` | `navigate` | `cross-site` | absent | absent | absent |
| iframe (same-origin) | `iframe` | `navigate` | `same-origin` | absent | absent | absent |
| Script tag (CDN) | `script` | `no-cors` | `cross-site` | absent | absent | absent |
| XHR same-origin | `empty` | `same-origin` | `same-origin` | absent | absent | only if explicitly set |
| XHR cross-origin CORS | `empty` | `cors` | `cross-site` | absent | present | only if explicitly set |
| fetch() cross-origin | `empty` | `cors` | `cross-site` | absent | present | absent |
| fetch() same-origin | `empty` | `same-origin` | `same-origin` | absent | absent | absent |
| embed element | `embed` | `navigate` | varies | absent | absent | absent |

### Invalid Combinations (instant bot flags)

| Combination | Why It's Impossible |
|---|---|
| `Dest: empty` + `Mode: cors` + `User: ?1` | User is only sent on navigate mode |
| `Dest: document` + `Mode: cors` | Document destination implies navigate mode |
| `Dest: empty` + `Mode: navigate` | Navigate implies document/iframe/frame/embed/object dest |
| `Dest: script` + `Mode: navigate` | Scripts don't navigate |
| `Dest: iframe` + `Mode: cors` | iframes use navigate mode |

### Accept Header by Request Type

| Request Type | Correct Accept Header |
|---|---|
| Top-level navigation | `text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9` |
| XHR/fetch for JSON | `*/*` or `application/json` (never the full navigation Accept) |
| Image subresource | `image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8` |
| Script subresource | `*/*` |

### Chrome Header Order (top-level navigation)

```
Host, Connection, Cache-Control, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform,
Upgrade-Insecure-Requests, User-Agent, Accept, Sec-Fetch-Site, Sec-Fetch-Mode,
Sec-Fetch-User, Sec-Fetch-Dest, Accept-Encoding, Accept-Language, Cookie
```

### WAF Detection Layers for Embed Requests

1. **Header consistency** — Cross-validate Sec-Fetch-* combinations, sec-ch-ua vs TLS fingerprint, header order vs claimed browser.
2. **TLS fingerprint correlation** — JA4+ fingerprinting. Headers claim Chrome but TLS matches Python/OpenSSL = instant detection.
3. **Session sequence analysis** — WAFs expect navigation -> subresources -> XHR. XHR without prior navigation is anomalous.
4. **Cookie state** — Legitimate embed requests arrive with cookies from prior navigation. XHR without session cookies is suspicious.
5. **CORS preflight expectation** — Cross-origin POST with custom headers must be preceded by OPTIONS. Missing preflight = non-browser.
6. **Origin validation** — Some WAFs maintain allowlists of known embed partners.
7. **Frame-ancestors/CSP cross-reference** — If site sends `frame-ancestors 'none'` but WAF sees `Sec-Fetch-Dest: iframe`, those aren't legitimate iframes.

### WebView Evasion (potential future technique)

Android/iOS WebViews often omit all Sec-Fetch-* and Client Hints headers. WAFs can't flag "missing Sec-Fetch = bot" because legitimate WebView traffic looks identical. Trades desktop Chrome impersonation for mobile WebView impersonation.

## License

Apache 2.0
