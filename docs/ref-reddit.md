# Reddit

Wafer handles Reddit at the transport level, without understanding posts,
comments, or other Reddit content. There are two routes:

| Request | Route |
|---|---|
| Reddit JSON read: `GET` of a `.json` path on `reddit.com`, `www.reddit.com` or `new.reddit.com`, or any path on `api.reddit.com` / `oauth.reddit.com` | **Android app API** (below). Falls back to the web route when the app route cannot serve the read, except a read Reddit refuses to every logged-out client (see "Refused reads"). |
| GraphQL: `POST https://gql-fed.reddit.com/` with `json=` or `body=` | **Android app API**: sent with the app's token and headers. The caller sends the persisted operation; wafer does not build or translate GraphQL. |
| New Reddit HTML, any other body or non-GET request, a request that speaks for an account (`Authorization` / `Cookie` per request or on the session, a logged-in `reddit_session` cookie) | **Web route**: the anonymous-session bootstrap. |
| Explicit `old.reddit.com` URL | Fetched as requested. A login wall is returned normally. Wafer never selects Old Reddit automatically or as a fallback. |

`reddit_app=False` on the session sends JSON reads through the web route too.

## Android app route (`wafer/_reddit_app.py`)

A logged-out web client asking for JSON gets the Shreddit network-security
gate, and since 2026-10-20 it keeps getting it after the bootstrap below
establishes the anonymous cookie set (a fresh real Chrome gets the same 403).
The official Android app reads listings from `oauth.reddit.com` with an
anonymous token, and threads, comments and profiles over GraphQL on
`gql-fed.reddit.com`. Wafer presents itself as one logged-out install of
release 2026.44.0's app, matching the header sets its decompiled HTTP stack
builds (verified 2026-10-31):

- **Token:** `POST https://www.reddit.com/auth/v2/oauth/access-token/loid`,
  HTTP Basic auth of the app's public client id and an empty secret, compact
  JSON body `{"scopes":["*","email","pii","adsread","adsedit"]}`. The grant is
  JSON (`access_token`, `expires_in` ~86400) plus an `x-reddit-loid` response
  header, the install's logged-out user id. The install keeps it and sends it
  on later mints, which return the same loid. There is no refresh grant: the
  app mints again.
- **REST reads:** `https://oauth.reddit.com/<same path and query>`. Path and
  query are passed through unchanged (no `raw_json` is added).
- **GraphQL:** the caller's payload is POSTed to `https://gql-fed.reddit.com/`.
  Reddit's answers to note (measured 2026-10-31; wafer returns them as they
  are): `PostComments` returns at most 200 comments per read whatever `count`
  asks, with `more` stubs and `pageInfo.hasNextPage` for the rest. A deleted
  comment's tree `node` is a `DeletedComment` with no `id`, because the app's
  query selects none; its `depth` and `parentId` place it.
  `json=` is serialized compactly in the caller's key order, as the app's
  writer does; `body=` is sent as given. The app sends only persisted
  operations: `{"operationName","variables","extensions":{"persistedQuery":
  {"version":1,"sha256Hash"}}}`, never query text. The operation headers are
  read from that payload and left out when it does not carry them.
- **Headers,** in the order the app adds them (`[x]` = sent when the install
  has a value):

  | Request (app client) | Headers |
  |---|---|
  | Mint (auth client, OkHttp) | `Authorization: Basic`, [`x-reddit-loid`], `X-Reddit-Http-QoS`, `X-Reddit-Device-Tier`, `User-Agent`, `x-reddit-compression`, `X-Reddit-QoS`, `X-Reddit-Media-Codecs`, `Client-Vendor-ID`, `X-Reddit-P-Device-ID`, `x-reddit-session`, `Content-Type: application/json; charset=UTF-8`, `Content-Length`, `Accept-Encoding: gzip` (OkHttp's BridgeInterceptor adds the last three in this order) |
  | REST read (REST client, OkHttp) | `X-Reddit-Http-QoS`, `X-Reddit-Device-Tier`, `x-reddit-compression`, `X-Reddit-QoS`, `X-Reddit-Media-Codecs`, `Authorization: Bearer`, `Client-Vendor-ID`, `x-reddit-device-id`, `User-Agent`, `X-Dev-Ad-Id`, `Device-Name`, `x-reddit-dpr`, `x-reddit-width`, [`x-reddit-loid`], `x-reddit-session`, `X-Reddit-P-Device-ID`, `Accept-Language: en-US`, `Accept-Encoding: gzip` |
  | GraphQL (Apollo over Cronet) | `content-length` (Chromium's `//net` sets it before the request's own headers), `X-Reddit-Retry: attempt=<n>, max=3`, [`X-APOLLO-OPERATION-NAME`], [`X-APOLLO-OPERATION-ID`], `accept: application/graphql-response+json, application/json`, `X-Reddit-Http-QoS`, `X-Reddit-Device-Tier`, `x-reddit-compression`, `X-Reddit-QoS`, `X-Reddit-Media-Codecs`, `Authorization: Bearer`, `Accept-Language: en-US`, `Client-Vendor-ID`, `x-reddit-device-id`, `User-Agent`, `X-Dev-Ad-Id`, `Device-Name`, `x-reddit-dpr`, `x-reddit-width`, [`x-reddit-loid`], `x-reddit-session`, `X-Reddit-P-Device-ID`, `Content-Type: application/json; charset=utf-8`, `Accept-Encoding: gzip, deflate` (added by `//net`; Cronet 143 leaves zstd off and the app does not enable brotli), `priority: u=1, i` (the HTTP/2 priority `//net` appends at Cronet's default MEDIUM priority) |

  wreq sends them in this order with nothing added (checked on the wire;
  wafer places `content-length` itself). `<n>` counts the route's own
  429/5xx retries. Header order comes from the app's interceptor code and
  Chromium 143's `//net` source; the app's own requests could not be
  decrypted (its network security config enforces Certificate Transparency
  on reddit.com, so an interception certificate fails).
- **Values:** `User-Agent: Reddit/Version <ver>/Build <build>/Android <n>`
  from `_APP_RELEASES` (real releases with each one's minimum Android; the
  Android part is `Build.VERSION.RELEASE`, a plain major since Android 13).
  `Client-Vendor-ID` and `x-reddit-device-id` are one uuid4 per install.
  The phone comes from `_PHONES` (`Device-Name: <manufacturer>;<model>`,
  `x-reddit-dpr` = density as Java prints a float, `x-reddit-width` =
  `(int) (widthPixels / density)`, and the phone's hardware decoders as
  `X-Reddit-Media-Codecs: available-codecs=video/avc, video/x-vnd.on2.vp9,
  video/hevc, video/av01` in the app's order). `X-Reddit-Device-Tier: v2t1` is
  the class the app gives a current flagship. `X-Reddit-QoS:
  down-rate-mbps=%.3f` is re-estimated per request around the install's rate,
  and `X-Reddit-Http-QoS` is its class (`EXCELLENT` >= 20 Mbps, `GOOD` >= 10,
  `STANDARD` >= 5, `LIMITED` >= 2, else `VERY_LIMITED`). `X-Dev-Ad-Id` is a
  per-install advertising id. `X-Reddit-P-Device-ID` is the lowercase hex
  SHA-384 of a per-install `ANDROID_ID`.
- **`x-reddit-session`** is the app's own analytics session, not a value the
  server hands out (the mint's `x-reddit-session` response header is ignored,
  as the app ignores it): `<18 [A-Za-z0-9]>.2.<created ms>.<key tag>-<HMAC>`,
  where the HMAC is the unpadded base64url HMAC-SHA512 of everything before
  the `-`, under the key every install ships (`_SESSION_SECRET`). Each wafer
  session starts its own, and replaces it after 30 minutes without a Reddit
  app request, as the app starts one when it returns to the foreground.
- **Not sent:** `x-reddit-height` (its value depends on how the Android
  version reports window metrics, and the app can omit it), translation and
  client-state headers (per-operation and per-locale), and
  `X-Reddit-Http-Cronet-Version` (it would name a Cronet whose TLS wafer does
  not reproduce; the app omits it before Cronet is up).
- **TLS and HTTP/2:** two wreq clients, as the app has two network stacks.
  Both were checked against the real app (2026.44.0 on an Android 16
  emulator, Conscrypt 360527520), whose ClientHellos were captured with the
  emulator's `-tcpdump`:
  - **OkHttp** (mint, REST reads): Android's Conscrypt, since the app bundles
    no TLS provider. `okhttp_tls_options()` reproduces the captured hello
    exactly: JA3 `771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-21,29-23-24,0`,
    JA4 `t13d1514h2_8daaf6152771_43ade6aba3df`, padded to a 512-byte record.
    The SCT extension (18) is there because the app's network security config
    turns Certificate Transparency on for reddit.com, redd.it,
    redditstatic.com and redditmedia.com. HTTP/2 is OkHttp's
    (`4:16777216|16711681|0|m,p,a,s`). Conscrypt is a Mainline module, so the
    hello is the same on every Android version the install picks. wreq's own
    `OkHttp5` profile is OkHttp's JVM hello (3DES, another cipher order); the
    token endpoint refuses it with the network-security 403.
  - **Cronet** (GraphQL): the app's embedded Cronet 143.0.7445.0 sends the
    same ClientHello as wreq's `Chrome143` on Android (identical `ja4_r`,
    JA4 `t13d1516h2_8daaf6152771_d8a2da3f94cd`), with Chrome's HTTP/2
    settings. `cronet_emulation()` pins that major; it is not
    `DEFAULT_EMULATION`.
  - Not reproduced: the app also hints `gql-fed.reddit.com` for QUIC and
    reaches it over HTTP/3 once Cronet is up; wreq has no QUIC transport, so
    wafer's GraphQL is what the app sends when UDP is blocked. Before Cronet
    starts, the app's first GraphQL requests go out on OkHttp.

### State and persistence

The install (device id, release, Android version, download rate, phone,
advertising and persisted device ids, loid) and the token are stored in
`cache_dir/reddit-app.state`, written `0o600` with an atomic
replace. The suffix keeps the cookie cache from reading it as a domain. A
session loads it on first use and, before minting, re-reads it in case another
session on the same cache minted since. A stored release that is no longer in
`_APP_RELEASES` keeps its device id and moves to a current build, as an updated
app would; an install saved before phones were modelled (or on a phone no
longer in `_PHONES`) keeps its device id and loid and gets a phone. Unknown
stored fields are ignored, so older files load. Without `cache_dir` the install lives for the session. Token, loid
and session values never appear in logs, reprs, or `reddit_bootstrap_state()`.

### Failure handling

| Answer | Behavior |
|---|---|
| 2xx JSON, Reddit's JSON errors (private subreddit 403, 404) | Returned as they are, `resp.emulation == "reddit_app"`. |
| 3xx to another app-readable URL | Followed on the app route (bounded by `max_redirects`); `resp.url` / `resp.history` show the caller's host. With `follow_redirects=False` the 3xx is returned and its `Location` names the caller's host. |
| 3xx elsewhere | This read goes to the web route (no backoff). A GraphQL POST's 3xx is returned as its answer, never followed. |
| 401 | A token minted more than 2 minutes earlier (a saved one, one revoked early) is dropped and reminted once. A fresh token's 401 is the API's answer for an endpoint that needs an account: a read goes to the web route, no remint, no backoff; a GraphQL POST returns the 401. |
| 429 JSON, or `x-ratelimit-remaining` below 1 on the previous answer | Wait for `x-ratelimit-reset` / `Retry-After` and retry if that fits the deadline with 2 s to spare (`max_retries` bounds 429 retries); otherwise this read goes to the web route (no backoff), never a `WaferTimeout`. |
| 5xx | Backoff and retry within `max_retries`, then returned. |
| Any non-JSON 2xx/4xx other than 429 (an HTML 403, the reCAPTCHA page) | **Block for this request only**: `RequestBlocked` (`challenge_type="reddit"`, the gate as `e.response`), or the gate returned under `max_rotations=0`. No web route, no backoff, other reads keep the app route. Reddit's rules are per path (r/all is refused while r/popular is served), and the web route refuses anonymous JSON as well, so falling back could only add a bootstrap (or a browser) per read. See "Refused reads". |
| A non-JSON 429 | Rate limiting, handled as a 429 above. |
| A token mint Reddit refuses (a 4xx other than 429, or a non-grant 200) | **Route held**: reads use the web route for 15 minutes. GraphQL POSTs keep the app route: with a held token they are sent, without one they raise `TokenMintFailed` (`stage="reddit_app"`, the mint's status) without minting again. Requests queued behind the refused mint do not mint either. |
| Transport error (mint or read), a mint answered 429 or 5xx | Reads use the web route for 1 minute. A GraphQL POST raises by the cause: `ConnectionFailed` (no answer), `RateLimited` (a 429 mint), `TokenMintFailed` (a 5xx mint), or `WaferTimeout` when the deadline passed. |

A GraphQL POST never goes out on the session's web identity: without the
app's token Reddit answers 401, so every case above that would hand it to the
web route raises instead (`TokenMintFailed`, `ConnectionFailed`, or
`RateLimited` when the rate-limit window will not reset in time). That
includes `resolve=` pins that leave `www.reddit.com` or `gql-fed.reddit.com`
unpinned: an anonymous GraphQL POST raises `ConnectionFailed` naming the
pins. A GraphQL POST that speaks for an account, or one on a
`reddit_app=False` session, goes out as asked.

`reddit_bootstrap_state()["app_last_outcome"]` names how the last app read
ended (`refused` for a block). A request that speaks for an account never takes the route: an
`Authorization` or `Cookie` header per request or in the session's headers, or
a logged-in `reddit_session` cookie in the jar.

`max_response_size` applies to app reads. The session rate limiter paces them
under the caller's host (the one in the requested URL). `resolve=` pins apply to
the app client, and the route is used only when `www.reddit.com` and the
request's app host (`oauth.reddit.com`, or `gql-fed.reddit.com` for GraphQL)
are pinned, so it never connects anywhere real DNS chose. An
`AsyncSession` mints under a lock, so concurrent cold reads share one token.

### Refused reads

Since 2026-10-20 (about 18:40 UTC) Reddit refuses these JSON reads to every
logged-out client (r/all was confirmed later the same day), with the same network-security 403 for the app's anonymous
token, an established anonymous web session and a fresh real Chrome (measured
2026-10-31): a thread and its comments (`/comments/<id>`,
`/r/<sub>/comments/<id>/...`), the comment streams (`/r/<sub>/comments`),
`/api/info`, `/api/morechildren`, `/user/<name>/about`, r/all in any form,
and `/by_id` with more than one id (`_ANON_REFUSED_PATH_RE`, matched with any
`.json` suffix removed; r/popular, names that only start with "all", and
`/by_id` with one id are served). Listings,
search, `/by_id`, `/duplicates`, `/r/<sub>/about`, wiki pages and a user's
overview, comments and submitted listings are still served. The token is not
the reason: with no token even listings are gated, a forged one gets a
different "Blocked" page, and the same token, TLS and headers read the same
thread and profile over GraphQL (`PostComments`, `UserProfileDetails`, both
200). The app never calls those REST paths.

Such a read still goes to the app route once, so it is served again if Reddit
reopens it. The gate then ends the request as a block (`RequestBlocked`, or
the response under `max_rotations=0`) without the web route, retries,
rotation or a backoff for other reads. Any other app-route gate is handled the
same way (r/all in any form, `/r/all/rising.json` included, was found the
same day). The web route applies the rule to the listed paths
(`reddit_gate_is_final`), and also treats a 403 gate that survives a solved
bootstrap as a block: the anonymous cookie set is in place and the answer is
still no, which no identity or browser changes. It then remembers that for 15
minutes: a later anonymous Reddit JSON read (`reddit_json_read`: a `.json`
path on any Reddit host, or an API host) ends at its gate without a bootstrap
or a browser. Without that, a held app route turned every read into a browser
bootstrap (fetchaller's parity gate, 2026-10-31). HTML pages and requests that
speak for an account are not affected.

### Maintenance

- `_APP_RELEASES` must be refreshed as the app updates (an install that never
  updates is unusual, and Reddit can retire old builds). Take the version
  names and version codes of current releases from the Play listing or an APK
  mirror listing, with each release's minimum Android.
- When a release is added, check its header sets against its decompiled HTTP
  stack (the interceptors that add `Client-Vendor-ID`, `x-reddit-dpr`,
  `X-Reddit-QoS`, the Apollo POST body writer, the mint's request body and the
  `x-reddit-session` signer and its key). `_PHONES` holds phones whose
  metrics and decoders are known; keep the shipped Android majors honest.
- `cronet_emulation()` follows the app's embedded Cronet (`libcronet.<version>.so`
  in the arm64 split), not wafer's newest Chrome. Bump it with the app.
- To re-capture the app's ClientHellos: Android SDK command-line tools,
  a `google_apis` arm64 image, `emulator -avd <avd> -no-window -tcpdump
  <file>`, `adb install-multiple` the bundle's base, arm64, density and
  language splits, then `svc wifi disable` (the capture sees only the
  emulator's eth0, and apps default to Wi-Fi) and launch the app. Read the
  hellos with `tshark -Y 'tls.handshake.type == 1' -T fields -e
  tls.handshake.extensions_server_name -e tls.handshake.ja3_full -e
  tls.handshake.ja4_r`.
- GraphQL persisted-query hashes belong to the caller. Wafer only forwards
  them; the app changes them as its operations change.

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
  Reddit URL, a form posting back with `captcha=1` added to the page's query
  (`?captcha=1`, or `&amp;captcha=1` when the URL already has a query, as a
  `/svc/shreddit/` partial's does) plus the `g-recaptcha` widget or the
  reCAPTCHA script. Until 2026-10-31 only the `?` form was recognized, so a
  cold session's first partial read returned the page as a 200. Reddit's login page loads reCAPTCHA but never posts to
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
  bootstrap retains the normal rotation escape hatch and unrelated hosts do not
  inherit a browser-pinned transport identity. A 403 gate on the replay after
  a solved bootstrap is a block instead (see "Refused reads"): no rotation. (A reCAPTCHA solve on Reddit is
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
3. A JSON error (a private or missing subreddit) comes back as Reddit's JSON.
4. A thread `.json` and a `/user/<name>/about.json` raise `RequestBlocked` in
   well under a second with `app_last_outcome == "refused"`, and a listing
   right after is still `reddit_app`.
5. `POST https://gql-fed.reddit.com/` with a `PostComments` and a
   `UserProfileDetails` persisted operation returns 200 GraphQL JSON as
   `reddit_app` (sync and async).
6. Drop the stored token and read again: the mint sends the stored loid and
   gets the same one back.

Web route (`reddit_app=False`, `max_rotations=0`):

1. A New Reddit HTML page from a cold session returns real content with one
   inline solve and only `www.reddit.com` automatic legs. A JSON listing gets
   one established bootstrap and then `RequestBlocked` (anonymous web JSON is
   refused since 2026-10-20), and a thread `.json` gets `RequestBlocked` with
   no bootstrap.
2. Recreate the session with the same cache and confirm both succeed without
   another inline solve.
3. To exercise browser recovery, force the inline parser leg to fail in a
   controlled test and confirm Chrome navigates only the fixed New Reddit root,
   followed by a successful wreq replay of the original URL.

If Reddit serves no cold gate during a run, a warm pass proves nothing. A cold
HTML page that meets the reCAPTCHA page should still return content after one
inline solve.

History: 2026-10-31, REST thread, comment, `/api/info`, `/api/morechildren` and
`user/about` reads found refused to every logged-out client since 2026-10-20;
those reads became blocks, GraphQL POSTs joined the app route, and the app's
2026.44.0 headers, mint body and signed analytics session were adopted. The
same day the app's OkHttp and Cronet ClientHellos were captured on an Android
16 emulator; the OkHttp client moved from Chromium TLS to the captured
Conscrypt hello and the GraphQL client to Chrome 143 (Cronet 143), and the
token mint, listings and GraphQL were re-verified live on both. All
app-route and web-route checks above passed live (the web route: bootstrap
established, then `RequestBlocked` without rotation).
2026-07-28, browser recovery verified (root only, 200 replay, no
rotation). 2026-09-27, the verification page's title and token field changed
(parser made structural), cold subreddit HTML started getting the reCAPTCHA
page (fresh Chrome too), and the app route landed; app-route and web-route
checks 1-2 passed, sync and async, `browser_attempts=0`.
2026-09-28, re-verified from the PyPI v0.7.0 install.
