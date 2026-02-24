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

resp.status_code   # int -HTTP status code
resp.ok            # bool -True if 200 <= status < 300
resp.text          # str -decoded body (lazy, UTF-8 with replacement)
resp.content       # bytes -raw body (preserved exactly for binary)
resp.headers       # dict[str, str] -lowercase keys
resp.url           # str -final URL after redirects
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
```

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
    max_rotations=1,     # fingerprint rotations on 403/challenge (switches to Safari)

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

All `**kwargs` are passed through to rnet (headers, params, json, form, data, timeout, etc.).

## TLS Fingerprinting

Wafer uses rnet's `Emulation` profiles to produce browser-identical TLS fingerprints (JA3, JA4, HTTP/2 SETTINGS frames, header order). Defaults to the newest Chrome profile.

```python
# Automatic -newest Chrome
session = SyncSession()

# Specific profile
from rnet import Emulation
session = SyncSession(emulation=Emulation.Chrome145)
```

The `sec-ch-ua` header is auto-generated to match the emulated Chrome version using the same GREASE algorithm as Chromium source.

On a 403 or challenge, wafer automatically switches from Chrome to Safari (fundamentally different TLS/H2 fingerprint) and retries. This is more effective than cycling between Chrome versions, which share nearly identical fingerprints.

## Opera Mini Profile

`Profile.OPERA_MINI` impersonates Opera Mini in Extreme/Mini data-saving mode. Bypasses rnet entirely -uses Python's stdlib `urllib` with system OpenSSL, producing a server-side proxy TLS fingerprint (OpenSSL, not BoringSSL). HTTP/1.1 only, no `Sec-Ch-Ua` or `Sec-Fetch-*` headers.

Because Opera Mini cannot execute JavaScript, **challenge detection, fingerprint rotation, retry logic, and browser solving are all disabled**. Rate limiting still applies. GET only (`ValueError` on other methods).

```python
from wafer import SyncSession, AsyncSession, Profile

with SyncSession(profile=Profile.OPERA_MINI) as session:
    resp = session.get("https://example.com")

async with AsyncSession(profile=Profile.OPERA_MINI) as session:
    resp = await session.get("https://example.com")
```

## Safari Profile

`Profile.SAFARI` impersonates Safari 26 on macOS (M3/M4 hardware). Uses rnet with custom `TlsOptions` and `Http2Options` instead of Chrome's `Emulation` profiles, producing a TLS+H2 fingerprint matching real Safari 26.2/26.3 M3/M4 exactly.

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

Wafer detects 16 WAF challenge types from response status, headers, and body:

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
| hCaptcha | `hcaptcha.com` script, `h-captcha` div |
| reCAPTCHA | `google.com/recaptcha` script, `g-recaptcha` div |
| Vercel | Vercel bot protection challenge |
| Generic JS | Unclassified JavaScript challenges |

When a challenge is detected, wafer:
1. Tries inline solving (ACW, Amazon, TMD - no browser needed)
2. Tries browser solver if configured (for JS-only challenges like Cloudflare, reCAPTCHA)
3. Switches from Chrome to Safari and retries
4. Raises `ChallengeDetected` if all attempts fail

## Inline Solvers

Three challenge types are solved without a browser:

- **ACW (Alibaba Cloud WAF)** -Extracts the obfuscated cookie value from the challenge page JavaScript, computes the XOR-shuffle, and sets the `acw_sc__v2` cookie.
- **Amazon CAPTCHA** -Parses the captcha form and submits it programmatically.
- **TMD (Alibaba TMD)** -Warms the session by fetching the homepage to establish a valid TMD session token.

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
- **Rotations** (`max_rotations=1`): For 403/challenge responses. On the first failure, wafer switches from Chrome to Safari (fundamentally different TLS/H2 fingerprint) and retries.

After `max_failures` consecutive failures on a domain, the session is retired (full identity reset). Set to `None` to disable.

### Exhaustion behavior

When all rotations are exhausted, wafer either raises or returns the response depending on the failure type:

| Failure | Default (`max_rotations > 0`) | Bulk (`max_rotations = 0`) |
|---------|-------------------------------|---------------------------|
| 403 + challenge detected | Raises `ChallengeDetected` | Returns response |
| 403 + no challenge | Returns response | Returns response |
| 429 | Raises `RateLimited` | Returns response |
| 5xx / empty 200 | Returns response | Returns response |
| Connection error | Raises `ConnectionFailed` | Raises `ConnectionFailed` |

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

```python
session = SyncSession(
    embed="xhr",
    embed_origin="https://seaway-greatlakes.com",
    embed_referers=["https://seaway-greatlakes.com/marine_traffic/en/marineTraffic_stCatherine.html"],
)
resp = session.get("https://www.marinetraffic.com/getData/get_data_json_4/z:11/X:285/Y:374/station:0")
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
    solve_timeout=30.0,   # max time per solve attempt
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

Supports: Cloudflare (managed + Turnstile), Akamai, DataDome (VM PoW + puzzle slider), PerimeterX (including press-and-hold), Imperva, Kasada, F5 Shape, AWS WAF, GeeTest v4 (slide puzzle), Alibaba Baxia (slider), hCaptcha (checkbox), reCAPTCHA v2 (checkbox + image grid via YOLO), and generic JS challenges.

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
5. Everything is returned in an `InterceptResult` for replay via rnet

## Mouse Recorder (Mousse)

Dev tool for recording human mouse movements used by the browser solver. Recordings drive PerimeterX press-and-hold, drag/slide puzzle solvers (GeeTest, Baxia/AliExpress), reCAPTCHA grid tile clicking, and browse replay (background mouse/scroll activity during all solver wait loops). Seven recording modes: idle, path, hold, drag (puzzle), slide (full-width "slide to verify"), grid (short tile-to-tile hops for reCAPTCHA 3x3 grids), and browse. See [`wafer/browser/mousse/README.md`](wafer/browser/mousse/README.md) for full documentation.

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
  _base.py          # BaseSession -shared config and logic, zero I/O
  _sync.py          # SyncSession -wraps rnet.blocking.Client
  _async.py         # AsyncSession -wraps rnet.Client
  _response.py      # WaferResponse wrapper
  _challenge.py     # Challenge detection (16 WAF types)
  _solvers.py       # Inline solvers (ACW, Amazon, TMD)
  _cookies.py       # JSON disk cache with TTL and LRU
  _fingerprint.py   # Emulation profiles, sec-ch-ua generation
  _profiles.py      # Profile enum (OPERA_MINI, SAFARI)
  _opera_mini.py    # Opera Mini identity generation + stdlib HTTP transport
  _safari.py        # Safari 26 identity -TLS options, H2 options, headers
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
    _recaptcha_grid.py  # reCAPTCHA v2 image grid solver (YOLO)
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
