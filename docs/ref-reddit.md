# Reddit

Wafer handles Reddit at the transport level, without understanding posts,
comments, or other Reddit content. There are two routes:

| Request | Route |
|---|---|
| Reddit JSON read: `GET` of a `.json` path on `reddit.com`, `www.reddit.com` or `new.reddit.com`, or any path on `api.reddit.com` / `oauth.reddit.com` | **Android app API** (below). Falls back to the web route when the app route cannot serve the read. |
| New Reddit HTML, anything with a body or a non-GET method, a request that speaks for an account (`Authorization` / `Cookie` per request or on the session, a logged-in `reddit_session` cookie) | **Web route**: the anonymous-session bootstrap. |
| Explicit `old.reddit.com` URL | Fetched as requested. A login wall is returned normally. Wafer never selects Old Reddit automatically or as a fallback. |

`reddit_app=False` on the session sends JSON reads through the web route too.

## Android app route (`wafer/_reddit_app.py`)

A logged-out web client asking for JSON gets the Shreddit network-security
gate, and clearing it through the web verification can escalate to a
reCAPTCHA. The official Android app reads the same listings from
`oauth.reddit.com` with an anonymous token, which is what every logged-out
install does. Wafer presents itself as one such install:

- **Token:** `POST https://www.reddit.com/auth/v2/oauth/access-token/loid` with
  HTTP Basic auth of the app's public client id and an empty secret, JSON body
  `{"scopes":["*","email","pii"]}`. The grant is JSON (`access_token`,
  `expires_in` ~86400) plus `x-reddit-loid` and `x-reddit-session` response
  headers, which later reads echo back.
- **Reads:** `https://oauth.reddit.com/<same path and query>` with
  `Authorization: Bearer`, the loid/session headers, and the device headers.
  Path and query are passed through unchanged (no `raw_json` is added).
- **Device identity:** `User-Agent: Reddit/Version <ver>/Build <build>/Android
  <n>` from a table of real Play releases (`_APP_RELEASES`, with each build's
  minimum Android), `client-vendor-id` and `x-reddit-device-id` (one uuid4 per
  install), `x-reddit-retry`, `x-reddit-compression`, `x-reddit-qos`
  (a per-install download rate) and `x-reddit-media-codecs`.
- **TLS:** Chromium's network stack on Android (`Emulation(profile=Chrome153,
  platform=Android, headers=False)`), on its own wreq client with no cookie
  jar. Measured 2026-09-27: an OkHttp 4.12 ClientHello gets Reddit's HTML
  network-security 403 on the token endpoint, while the Chromium one is served.
  With `headers=False` only the app's headers go out (wreq adds nothing but the
  transport's own; Accept-Encoding is set to Chromium's
  `gzip, deflate, br, zstd`).

### State and persistence

The install (device id, release, Android version, download rate) and the token
are stored in `cache_dir/reddit-app.state`, written `0o600` with an atomic
replace. The suffix keeps the cookie cache from reading it as a domain. A
session loads it on first use and, before minting, re-reads it in case another
session on the same cache minted since. A stored release that is no longer in
`_APP_RELEASES` keeps its device id and moves to a current build, as an updated
app would. Without `cache_dir` the install lives for the session. Token, loid
and session values never appear in logs, reprs, or `reddit_bootstrap_state()`.

### Failure handling

| Answer | Behavior |
|---|---|
| 2xx JSON, Reddit's JSON errors (private subreddit 403, 404) | Returned as they are, `resp.emulation == "reddit_app"`. |
| 3xx to another app-readable URL | Followed on the app route (bounded by `max_redirects`); `resp.url` / `resp.history` show the caller's host. With `follow_redirects=False` the 3xx is returned and its `Location` names the caller's host. |
| 3xx elsewhere | This read goes to the web route (no backoff). |
| 401 | A token minted more than 2 minutes earlier (a saved one, one revoked early) is dropped and reminted once. A fresh token's 401 is the API's answer for an endpoint that needs an account: this read goes to the web route, no remint, no backoff. |
| 429 JSON, or `x-ratelimit-remaining` below 1 on the previous answer | Wait for `x-ratelimit-reset` / `Retry-After` and retry if that fits the deadline with 2 s to spare (`max_retries` bounds 429 retries); otherwise this read goes to the web route (no backoff), never a `WaferTimeout`. |
| 5xx | Backoff and retry within `max_retries`, then returned. |
| Any non-JSON 2xx/4xx (an HTML 403, the reCAPTCHA page, an edge 429), a token mint Reddit refuses (a 4xx other than 429, or a non-grant 200) | **Route refused**: this read and every Reddit read for 15 minutes use the web route. |
| Transport error (mint or read), a mint answered 429 or 5xx | This read and every Reddit read for 1 minute use the web route. |

`reddit_bootstrap_state()["app_last_outcome"]` names how the last app read
ended. A request that speaks for an account never takes the route: an
`Authorization` or `Cookie` header per request or in the session's headers, or
a logged-in `reddit_session` cookie in the jar.

`max_response_size` applies to app reads. The session rate limiter paces them
under the caller's host (the one in the requested URL). `resolve=` pins apply to
the app client, and the route is used only when both `oauth.reddit.com` and
`www.reddit.com` are pinned, so it never connects anywhere real DNS chose. An
`AsyncSession` mints under a lock, so concurrent cold reads share one token.

### Maintenance

`_APP_RELEASES` must be refreshed as the app updates (an install that never
updates is unusual, and Reddit can retire old builds). Take the version names
and version codes of current releases from the Play listing or an APK mirror
listing, with each release's minimum Android.

## Web route: anonymous-session bootstrap

The web solver is browser-free. It uses the exact wreq client, cookie jar, and
TLS fingerprint that received the gate. A configured browser is only used as a
fallback when that inline path cannot establish the anonymous cookie set.

### Detection

- **403 JSON gate:** `theme-beta` in the first 4 KiB plus the
  network-security copy (`blocked by network security`, whitespace and case
  tolerant). Shreddit's private or quarantined subreddit 403 pages also carry
  `theme-beta`, hence both markers.
- **200 verification page:** recognized by structure, never by wording. On a
  Reddit URL any 200 is parsed; without a URL (external callers of
  `detect_challenge`) the page must carry one of the titles Reddit has served
  (`Reddit`, `Reddit - Please wait for verification`).
- **200 reCAPTCHA gate** ("Prove your humanity", first seen 2026-09-27): on a
  Reddit URL, a form posting to `?captcha=1` plus the `g-recaptcha` widget or
  the reCAPTCHA script. Reddit's login page loads reCAPTCHA but never posts to
  `?captcha=1`. A cold, cookieless navigation to a subreddit page gets this
  page directly, from a fresh real Chrome as much as from wafer (measured
  2026-09-27 with a headed Chrome net log: one GET, answered with the gate),
  while the root still serves the JS verification, and the cookies that earns
  clear the page. So the first time a request meets it, wafer runs the
  bootstrap below and replays; only a captcha that survives the bootstrap is
  treated as `recaptcha`: with `browser_solver` the reCAPTCHA solver runs on
  the URL, without one the response is returned (`max_rotations=0`) or
  `ChallengeDetected` raised, never passed off as content. The browser
  passthrough rejects both pages as content.

### Verification parser (`_parse_reddit_verification`)

Tolerant of cosmetics, strict on what a browser would act on. Reddit renamed
the title (`Reddit - Please wait for verification` to `Reddit`) and the token
field (`token` to `jsc_token`) on 2026-09-27 without changing the challenge;
both shapes parse.

- Body at most 64 KiB, `<noscript>` content ignored.
- Exactly one form, method GET, action the fixed New Reddit root (any
  same-origin path for detection only).
- Submitted fields: controls a submitter-less `requestSubmit()` leaves out
  (submit, button, image, reset) are skipped; the rest must be 2-8 hidden
  inputs with unique names `[A-Za-z0-9_-]{1,64}` and values
  `[A-Za-z0-9_.:/%-]{0,256}`. A `select`, `textarea`, `disabled` input, or any
  control with a `form=` attribute is rejected (the browser's form data would
  differ from the parse).
- Exactly one script with exactly one calculation: an immediately invoked
  function over a quoted seed (`(async e=>e+e)("s")`, `((e)=>{return e+e})`,
  `(async function(e){return e+e})`, backtick seeds). Its body must be the
  parameter doubled; any other computation fails closed. The regex uses
  anchored bodies and possessive whitespace, so it stays linear on hostile
  input (a 64 KiB whitespace run once took minutes).
- The same script fills exactly one field (`.elements.namedItem("x")`,
  `.elements["x"]`, `.elements.x` or `querySelector('[name=x]')`, then
  `.value =`), which must be one of the form's empty fields, and calls
  `requestSubmit()` or `submit()`.
- The solution is the seed doubled; fields are submitted in document order
  under the names the page used. Served JavaScript is never evaluated.

### Sequence

```text
original Reddit request
  -> 403 JSON gate, 200 HTML verification gate, or 200 reCAPTCHA gate
  -> cache any gate Set-Cookie headers
  -> GET https://www.reddit.com/        (a typed-URL navigation: no Referer)
  -> parse the verification form
  -> GET the solved form submission     (as the page's script sends it)
  -> cache and validate response-scoped Set-Cookie names
  -> discard the solved homepage without reading its body
  -> replay the original URL once, whether JSON or HTML
```

The submission matches what Chrome 153 sends for a script-initiated
`requestSubmit()` of a GET form (captured locally 2026-09-27):
`Sec-Fetch-Site: same-origin`, `Sec-Fetch-Mode: navigate`,
`Sec-Fetch-Dest: document`, `Referer: https://www.reddit.com/`, and **no**
`Sec-Fetch-User` (no user activation). Removing a header wreq's emulation adds
takes a per-request `default_headers=False` with the full header set (the
client's `orig_headers` still orders it and the jar still supplies cookies).
Client Hints the verification response asked for with `Accept-CH` are
included. Non-Chromium profiles send the same Referer and Sec-Fetch-Site.

If any inline leg fails and the session has `browser_solver=`, wafer performs
one browser recovery before fingerprint rotation:

```text
failed inline bootstrap
  -> navigate the browser to https://www.reddit.com/
  -> wait briefly for anonymous cookies
  -> reload that HTML root at most once
  -> require loid plus token_v2 or csv, scoped to Reddit
  -> import browser cookies without pinning the session-wide fingerprint
  -> replay the original request through wreq
```

The browser never navigates or reloads the blocked JSON URL. Browser HTML is
never returned as the response to the original request. Reddit's fixed solve
origin also takes precedence over a session-level `solve_origin`.

### Cookies and persistence

A successful solved response must itself set `loid` and either `token_v2` or
`csv`. Existing jar contents are not accepted as proof that the current solve
succeeded. Browser recovery requires the same cookie-name evidence from cookies
applicable to the Reddit solve origin. Only cookie names are examined; values
are never logged.

All Reddit bootstrap legs are persisted under the canonical `reddit.com`
`CookieCache` namespace. Session-cookie semantics are unchanged: only cookies
with an expiry survive process recreation. Identity rotation clears the
canonical namespace and any older host-specific Reddit namespaces together.

### Limits, retries, and concurrency

- The verification document is capped at 64 KiB; the large JSON gate and the
  reCAPTCHA page (~170 KB, mostly an inline image) are read up to 256 KiB as
  internal challenge overhead. The caller's `max_response_size` still applies
  unchanged to the final response, including a gate that is handed back
  unsolved (`ResponseTooLarge`).
- The fixed browser root is likewise internal solve overhead and is never
  returned or measured against the caller's final response limit.
- Every verification leg recomputes the remaining overall request deadline.
- A successful bootstrap counts as one inline solve and consumes no fingerprint
  rotation.
- Each original request attempts the bootstrap at most once.
- A configured browser fallback runs only after inline failure and before any
  fingerprint rotation. Without a browser, failure behavior is unchanged.
- Reddit's anonymous cookies do not pin the session fingerprint, so a failed
  replay retains the normal rotation escape hatch and unrelated hosts do not
  inherit a browser-pinned transport identity. (A reCAPTCHA solve on Reddit is
  an ordinary `recaptcha` solve and does pin, since its clearance may be bound
  to the solving browser.)
- `AsyncSession` serializes Reddit bootstrap work with a per-session lock. A
  successful inline or browser bootstrap generation lets concurrent requests
  replay once, but only while the exact solved client generation is still
  current.
- Cancellation and deadline expiry release the async lock.

Malformed verification, non-2xx legs, missing response cookie evidence, or a
client replacement cause a safe failure or a restart on the replacement client
under the same deadline. Wafer never falls back to Old Reddit.

## Request pacing

Wafer needs no pacing between Reddit requests and adds no delay of its own.
The one limit is the app API's budget: 100 reads per 10-minute window (a
sustained average of one read every 6 s; bursts are fine). A spent window
makes the next read wait for the reset when that fits its `timeout=`, and
otherwise sends it through the web route. At one read every 6 s or more
(`rate_limit=6` or higher), a window never holds more than 100 reads, so the
limit is never reached. The budget is Reddit's, not a host's: `rate_limit`
spaces each hostname separately, so `www.reddit.com` and `api.reddit.com` reads
together can go faster, and so can sessions that share a `cache_dir` (one app
install, one budget).

## Diagnostics

`session.reddit_bootstrap_state()` reports both routes, value-free: the inline
bootstrap (`attempts`, `successes`, `last_outcome`, `last_status`,
`last_cookie_names`), the browser recovery (`browser_attempts`,
`last_browser_outcome`, `last_browser_budget`), the jar (`cookie_names`,
`has_cookie_evidence`) and the app route (`app_reads`, `app_token_mints`,
`app_fallbacks`, `app_last_outcome`, `app_last_status`).

## Live verification

For contributors checking the solvers against live Reddit; not a usage rule
(see "Request pacing"). Space test requests 15-30 s apart so a burst of test
traffic does not change what Reddit serves. Use wafer directly and an empty
temporary cache.

App route:

1. Cold `SyncSession(cache_dir=tmp)`: a JSON listing returns 200 with
   `resp.emulation == "reddit_app"`, `app_token_mints == 1`, `attempts == 0`,
   `browser_attempts == 0`, and `reddit-app.state` is `0o600`.
2. A recreated session (and an `AsyncSession`) on the same cache reads without
   minting (`app_token_mints == 0`).
3. A post permalink `.json` (a two-listing array) and a JSON error (a private or
   missing subreddit) come back as Reddit's JSON.

Web route (`reddit_app=False`, `max_rotations=0`):

1. A JSON listing and a New Reddit HTML page from cold sessions return real
   content with one inline solve and only `www.reddit.com` automatic legs.
2. Recreate the session with the same cache and confirm both succeed without
   another inline solve.
3. To exercise browser recovery, force the inline parser leg to fail in a
   controlled test and confirm Chrome navigates only the fixed New Reddit root,
   followed by a successful wreq replay of the original URL.

If Reddit serves no cold gate during a run, a warm pass proves nothing. A cold
HTML page that meets the reCAPTCHA page should still return content after one
inline solve.

History: 2026-07-28, browser recovery verified (root only, 200 replay, no
rotation). 2026-09-27, the verification page's title and token field changed
(parser made structural), cold subreddit HTML started getting the reCAPTCHA
page (fresh Chrome too), and the app route landed; app-route and web-route
checks 1-2 passed, sync and async, `browser_attempts=0`.
2026-09-28, re-verified from the PyPI v0.7.0 install.
