# Changelog

All notable changes to wafer. Versions come from git tags (`hatch-vcs`); each
release is on [PyPI](https://pypi.org/project/wafer-py/) and
[GitHub Releases](https://github.com/Averyy/wafer/releases).

## 0.7.12 - 2026-11-04

### Changed

- **The default identity presents Chrome 157, the current stable release,
  over the Chrome154 TLS profile.** wreq's newest Chrome profile is 154, and
  real Chrome 154 through 157 send the same ClientHello and HTTP/2 settings
  (JA4 `t13d1517h2_8daaf6152771_cb7bf5808d99`, measured on Chrome 156 for
  macOS and 157 for Linux). The UA, `sec-ch-ua`, the high-entropy full
  version (`157.0.8103.38`) and the navigation `Accept`, which names
  `image/jxl` from Chrome 156, now follow 157; `chrome_full_version(
  Emulation.Chrome154)` returns `157.0.8103.38`. A rotation to an older
  Chrome profile presents its own version and Accept, and a session pinned to
  a solving browser presents the browser's. A browser of 155-157 now pins to
  Chrome154 as an exact match, without the "TLS shape may diverge" warning.
  Why: in one window from a Linux image, www.ebay.ca's Akamai refused
  alternating cold requests claiming Chrome 154 (403 "Error Page", 3 of 3) and
  served the same requests claiming 157 (200, 3 of 3), while stock Google
  Chrome stable 157 there was served 3 of 3 and Chrome for Testing 154 was
  refused. eBay's verdict also moves with other state: later the same day
  both claims were refused (and stock Chrome got eBay's splash), and after a
  pause both were served. So the version is one input a WAF reads, and an
  outdated one costs requests when it does.
- **A browser that would inherit UTC runs on Europe/London.** With no
  `timezone=` and no `TZ`, a container's browser ran on UTC, and Kasada
  refused every signed call from it (costco.com's own page call, 0 of 2)
  while accepting every named zone tried from the same Canadian IP
  (America/Toronto, America/Vancouver, Europe/London, Asia/Tokyo). London
  keeps UTC's offset in winter; `timezone=` or `TZ` still choose the real
  zone, and an explicit `TZ=UTC` is kept (with the existing warning).

### Fixed

- **Akamai's bm-verify interstitial is answered inline**
  (www.amazon.co.uk). It is a 200, 2.2 KB page whose script posts a token
  and a trivial proof of work to `/_sec/verify?provider=interstitial` and
  reloads, and it was returned as the page (5 of 8 cold requests claiming
  Chrome 154 from a Linux image, at times; none in 9 claiming 157). It is now
  classified `akamai`, and the session makes the script's POST over the
  transport, shaped as Chrome's XHR (fetch metadata, Chrome's captured
  fetch() header order, no navigation-only headers), and replays: the
  results page 3 of 3 (1.3-1.5 MB, about 2s in all). The same POST sent with
  the navigation client's headers got `{"reload": true}` too, but its replay
  drew Amazon's own "503 Service Unavailable" page 2 of 4.
- **Akamai sites solve again in a Linux container** (homedepot.com, every solve
  timed out at about 142s). The browser's user-agent override set its
  languages, which made Chrome send Accept-Language right after User-Agent
  instead of last, an order no stock Chrome has. homedepot.com's Akamai
  refused that order outright from Linux and Windows (403 "Error Page" on the
  first request, before any sensor ran) and let macOS through. The languages
  now come from `--accept-lang=en-US,en` in `hardened_launch_config()`, so
  Chrome places the header itself. `navigator.languages` and the header value
  stay exactly `en-US,en` whatever the host's language (measured on French
  Linux and macOS hosts).
- **Akamai's refusal page gets one retried navigation instead of the whole
  solve budget.** A cold navigation Akamai distrusts can get a small 403/429
  "Error Page" that loads its script; once that script has posted, the same
  navigation goes through (www.ebay.ca from Chrome for Testing 154 on
  Linux). The handler
  polled it to the deadline. Now it waits for the script, retries once, and
  gives up about 15s after a refusal that survives the retry. A 403/429 that
  sets Akamai's `bm_so` cookie is classified `akamai`; it read as
  `generic_js`.
- **eBay's own splash challenge is detected.** eBay redirects a request it
  wants to check to `/splashui/challenge`, a 200 "Pardon Our Interruption"
  page that a browser clears in about a second. wafer returned it as the
  page. It is now `generic_js`, solved in the browser, and never returned as
  a browser passthrough.
- **Cloudflare challenges that come in stages are solved through to the
  page** (stackoverflow.com). The first stage sets `cf_clearance`, and
  Cloudflare can then answer the form POST carrying it with another
  challenge (a 429 with Turnstile, sometimes a 403 after that). The solve
  returned on the first stage's clearance, the replay got the 429, and the
  session retired. A clearance now counts only once the page's newest
  document is not a challenge. The "no Turnstile iframe after 3s, so the
  browser passed through" shortcut no longer fires while a challenge
  document is still in the page (a slow first stage outlasted it), and a
  challenge with no iframe that does not move for 20s fails the solve. A
  challenge after a redirect to another origin is that origin's, not a next
  stage: it is left to the replay as before (www.glassdoor.com 301s to
  www.glassdoor.ca, and Cloudflare challenges both).
- `render()` classified that 429 stage as `generic_js` and never ran the
  Turnstile handler. Cloudflare's body markers now count on a 429 as on a
  403/503, and a render's in-place solve gets the page's documents as the
  solve path does. A render whose page cleared a Cloudflare challenge while
  it loaded now reports `challenge_absent=False`, so the session pins to the
  browser and its next request is not challenged under its own identity.
- **Kasada-signed APIs** (costco.com's search API). Such an API refuses a call
  without the per-request `x-kpsdk-ct/-cd/-h/-v` headers the site's script
  adds, with a bare 403/429 in its own content type (429, empty
  `text/plain`), and cookies do not help. That response skipped detection as
  non-HTML and was retried and raised as `RateLimited`. It is now classified
  `kasada` whatever its content type. With a `browser_solver`, the browser
  opens the page the call comes from (the request's `Referer`, else its
  `Origin`, else `embed_origin`; `solve_origin` overrides) and makes the
  request there through the site's own script, and its response is returned,
  without the page's cookies: the site's own page calls these APIs without
  cookies, and costco.com's consent cookie gets its location API refused.
  Its redirects count against `max_redirects` (past it, `TooManyRedirects`).
  A `multipart=` request is not made in the page, since its body cannot be
  read back, and keeps the usual solve.
  Each refused call goes through the browser. Kasada scores the browser that
  signs; see the UTC change above.
- **Imperva's in-page replay no longer sends a `multipart=` request without
  its upload.** wreq's multipart body cannot be read back, so the XHR went
  out empty and its 2xx was returned as the answer. It now falls back to
  cookie replay over wreq, which still has the body.
- **A browser solve that times out no longer leaves a dead browser for the
  next one.** Recovering the stuck worker makes Playwright's driver close
  Chrome, but the browser keeps reporting itself connected until a later call
  happens to deliver the disconnect. When the cut-off call returned without
  delivering it, the next solve started on the closed browser and failed at
  once with `TargetClosedError`, whatever its timeout. A Kasada-signed
  costco.com call cut off in its SDK wait did this 3 of 3 in a Linux image,
  and the next call returned the unsigned 429 in 0.1-0.4s. The solver now
  relaunches after any interrupted operation, and does not report itself
  ready in the meantime: the next call was signed (200 in about 20s).
- **`render()` no longer reports "no document" when the page moves on by
  itself.** eBay's splash (`/splashui/challenge`) settles and then navigates
  to the search a second later; in a slow Linux image, the DOM read raced
  that commit, failed, and render raised `ConnectionFailed` ("browser render
  produced no document") about 7s in with most of its budget left, 10 of 22
  eBay renders over 0.7.11 and the working tree. A read that comes back empty
  now waits for the new document, lets it settle and reads again (up to three
  times); a document over the size cap still raises `ResponseTooLarge`.
  Live in the same image: 6 of 6 renders returned the results, and 2 of them
  had hit the race and read again.
- **`render()` classifies an interstitial with its real headers.** It
  classified the document by its status and body alone, so Akamai's refusal
  page (a 403 whose `Set-Cookie` names `bm_so`) read as `generic_js` in
  render while the transport path called it `akamai`. The generic wait
  re-navigated it and then polled it for render's 30s post-solve window. It
  now gets the Akamai handler, as a `get()` solve does: from fetchaller's
  Linux image, 10 of 15 eBay renders went on to the results after the one
  retried navigation, and the 5 refused again were reported as the challenge
  in about 22s instead of 37s.
- **`render()` keeps the page a solve left in place.** After an in-place
  solve, render navigated to the URL again to capture it. When the solve
  had already ended on the requested page, that second navigation only asked
  the WAF again, and eBay's Akamai refused it (403), so render polled the
  refusal and returned it with the results already in hand. A page that is
  the requested URL, a 2xx document, past 10 KB and no challenge is now kept;
  anything else (TMD's small transition shell) is still replayed.
- **A browser solve no longer hangs on a mouse move Chrome never answers.**
  Chrome answers an input event once the page has handled it, and drops the
  answer when the frame it went to is torn down mid-dispatch. On mouser.com,
  DataDome's full-page iframe is removed when the cleared page reloads, and
  a move sent a few milliseconds before that reload committed never
  returned: the solve waited in `mouse.move` until its timeout (about 85s
  at `timeout=90`), the browser was killed to recover, and the request
  failed with the challenge (2 of 16 capped solves on macOS, 0.7.11 and this
  tree alike). Under `hardened_driver_env()`, which `BrowserSolver` always
  uses, an input command still unanswered after 3s is taken as answered;
  measured answers take 11 ms at the median and 354 ms at the slowest.
  Live, with the fix: 16 capped solves, 3 of them lost an answer and went on
  to the page (200 in 8.5-9.0s).
- **A DataDome solve where DataDome let the browser through is kept.** When
  DataDome trusts the browser's request it serves the page and sets its
  `datadome` cookie on that first response, so no challenge appears and no
  cookie changes. The handler counted that as a failed solve and the
  solver dropped the page and the cookie, so the request failed with the
  challenge (mouser.com, 1 of 16, in 14s). When the displayed document is a
  2xx and a `datadome` cookie is set for its host, it now counts as solved:
  the page is passed through and the session pins to the browser, as after
  any DataDome solve.

## 0.7.11 - 2026-11-02

### Fixed

- **Cookies set with `add_cookie()` now reach the browser.** `render()`,
  `browser_prime()`, `browser_solve_challenge()` and automatic browser solves
  each run in a fresh browser context, and that context never saw the
  caller's cookies. A page loaded with the site's defaults for the egress IP,
  and the site's value then replaced the caller's in the jar. With an
  AliExpress currency pin to GBP on a Canadian IP, `get()` was priced in GBP,
  `render()` in CAD, and every `get()` after the render in CAD. Now the
  browser starts with the session's `add_cookie()` cookies for the site being
  navigated, at their current jar value and scope. The same run stays in GBP
  throughout. Only cookies the caller added are carried; cookies the session
  earned from responses or solves are not, so a solve's context is otherwise
  as fresh as before. WAF clearance and sensor cookies (`cf_clearance`,
  `datadome`, `_abck`, `aws-waf-token`, `_px*`, `reese84`, `x5sec`, ...) are
  never carried in, even when the caller added them. Several solvers take one
  of those cookies being present as a finished solve.
- A seeded cookie the browser hands back unchanged is no longer counted as
  earned state. It is not written to `cache_dir` as solver state, and a
  `browser_prime()` that got nothing else returns False. A value the page
  changed still replaces the jar's, as a `Set-Cookie` on `get()` would.
- `BrowserSolver.solve()`, `asolve()`, `render()` and `arender()` take an
  optional `cookies=` (Playwright `add_cookies` entries) to seed the context.
  A custom `browser_solver` without it keeps working and is not passed any.
- Completing a certificate chain through AIA, an AIA intermediate expiring,
  and `mint_recaptcha_v3()` in an embed session no longer empty the session's
  cookie jar. Each rebuilt the client with a fresh jar, which dropped every
  in-memory cookie, the caller's included, and kept only what `cache_dir`
  held. Fingerprint rotation, `rotate_every` and session retirement still
  start an empty jar, as before.

## 0.7.10 - 2026-10-31

Reddit changed what it serves to logged-out clients on 2026-10-20. These
changes follow it and make wafer's Reddit requests match the official Android
app's.

### Changed

- **Reddit reads that Reddit refuses to every logged-out client fail fast.**
  This covers threads and their comments (`/comments/<id>`,
  `/r/<sub>/comments/<id>/...`), the comment streams (`/r/<sub>/comments`),
  `/api/info`, `/api/morechildren`, `/user/<name>/about`, `r/all` in any
  form, and `/by_id` with more than one id. Reddit refuses them to the app's anonymous token, to an anonymous web
  session and to a fresh browser alike. They raise `RequestBlocked`
  (`challenge_type="reddit"`, the 403 page in `e.response`), or return that
  response under `max_rotations=0`, in well under a second. The same data is
  available over GraphQL (see Added).
- **A gate on one Reddit read ends only that read.** It no longer sends every
  Reddit read to the web path for 15 minutes. Reddit's rules are per path, so
  other reads keep using the app route. Only a token mint Reddit refuses still
  holds reads for 15 minutes.
- **On the web path, a Reddit 403 that survives a solved bootstrap is
  `RequestBlocked` instead of a rotation.** The session then ends later
  anonymous Reddit JSON reads at their gate for 15 minutes, with no new
  bootstrap and no browser. HTML pages and requests made for an account are
  not affected.
- An HTML 429 from Reddit's app API is handled as rate limiting, not as a
  gate.
- **The Reddit app route matches the official Android app (release
  2026.44.0)** from its decompiled HTTP stack and captures of the real app on
  Android 16:
  - Header sets and order for each kind of request.
  - The token request's scopes.
  - The app's own signed `x-reddit-session`; the server's value is no longer
    echoed.
  - A logged-out id (loid) kept by the install and sent on later mints.
  - A modelled phone (device name, display metrics, video decoders).
  - Network quality reported per request.
  - Releases 2026.42 to 2026.44 on Android 13 to 16.
- **Reddit app route TLS:**
  - Token mints and REST reads send the app's OkHttp ClientHello on Android's
    Conscrypt (JA4 `t13d1514h2_8daaf6152771_43ade6aba3df`) with OkHttp's
    HTTP/2 settings, instead of Chromium's.
  - GraphQL sends the ClientHello of the app's Cronet 143, which is Chrome
    143's.
- With `resolve=`, GraphQL takes the app route only when `gql-fed.reddit.com`
  and `www.reddit.com` are pinned; otherwise an anonymous GraphQL POST raises
  `ConnectionFailed` instead of going out unauthenticated.

### Added

- **Reddit GraphQL.** `POST https://gql-fed.reddit.com/` with `json=` or
  `body=` goes out as the app: its token and headers, plus
  `X-APOLLO-OPERATION-NAME` / `-ID` taken from the payload. Send the app's
  persisted operations, for example `PostComments` for a thread and
  `UserProfileDetails` for a profile. The response is Reddit's GraphQL JSON,
  returned as is with `resp.emulation == "reddit_app"`.
  - A GraphQL POST is never sent without the app's token. When the route
    cannot send it, it raises according to the cause: `TokenMintFailed`
    (`stage="reddit_app"`) when the token endpoint answered without a grant,
    `ConnectionFailed` when it could not be reached or `resolve=` leaves a
    needed host unpinned, `RateLimited`, or `WaferTimeout`.
  - A redirect or a 401 comes back as Reddit's answer.
- `reddit_bootstrap_state()["app_last_outcome"]` can be `"refused"`.

### Fixed

- A single gated Reddit read no longer turns every later read into a web
  bootstrap. With `browser_solver` set, each of those bootstraps opened a
  browser.
- `reddit-app.state` files written by earlier versions keep their install id
  and loid.
- A cold session's first `/svc/shreddit/` partial read (such as the related
  posts rail) returned Reddit's "Prove your humanity" page as an ordinary 200.
  The page's form posts to `...?render-mode=partial&amp;captcha=1`, and only
  `?captcha=1` was recognized. It now runs the browser-free bootstrap and
  replays the read.

## 0.7.9 - 2026-10-25

- Brave Search proof-of-work gate solved in headed and headless browsers,
  including its large HTTP 429 interstitial, with spare tokens kept for the
  session.

## 0.7.8 - 2026-10-25

- Experimental Google SearchGuard detection, solved without launching a
  browser. A successful Google `/search` result through it is still
  unverified.
- Stricter AliExpress MTop live diagnostic.
- GitHub Releases are created after each PyPI publish.

## 0.7.7 - 2026-10-08

- The browser driver survives detached-element errors, and a dead driver
  fails fast.
- A browser solve keeps the session's cookie jar.
- New `BrowserSolver(timezone=)` option.

## 0.7.6 - 2026-10-08

- Akamai solves on GPU-less Linux.
- Cookies a site rejected are kept out of `cache_dir`.
- Hardened reCAPTCHA rounds.

## 0.7.5 - 2026-10-08

- A Chrome version mismatch within the same major is logged at DEBUG.

## 0.7.4 - 2026-10-07

- Rejected Akamai behavioral challenges give up early.

## 0.7.3 - 2026-10-07

- Fixed a DOM leak in browser passthrough, Opera Mini redirects and an Akamai
  false positive.

## 0.7.2 - 2026-10-07

- Headless Chrome matches headed Chrome in every frame and worker.
- reCAPTCHA success detection fixed.

## 0.7.1 - 2026-10-05

- AliExpress MTop reCAPTCHA solved.
- Moved to wreq 0.13.

## 0.7.0 - 2026-09-28

- Reddit JSON reads go through Reddit's Android app API by default
  (`reddit_app=`).
- Reddit's verification page is parsed by its structure, and its "Prove your
  humanity" page is detected.
- A navigation with a Referer sends the matching `Sec-Fetch-Site`.
- Client Hints are sent the way Chrome sends them.

## 0.6.x - 2026-09-07 to 2026-09-26

- Inline solvers for proof-of-work gates (redflagdeals) and site-owned cookie
  gates.
- wafer's own User-Agent for desktop Chrome, Edge and Firefox.

## 0.5.0 - 2026-09-03

- Incomplete TLS certificate chains are completed by following the leaf's AIA
  URL, with every hop verified by signature.

## 0.4.x - 2026-07-27 to 2026-08-10

- iOS Safari profile.
- Browser-rendered fetch.
- `RequestBlocked` for terminal WAF blocks.
- DNS sinkhole diagnosis.
- Solvers for Radware Bot Manager, Imperva in place, Baxia and Alibaba TMD.
- Exported hardened browser launch configuration.

## 0.3.x - 2026-07-03 to 2026-07-26

- `timeout=` is a total budget, plus a new `attempt_timeout`.
- Cross-family fingerprint rotation.
- Browser-free reCAPTCHA v3 tokens.
- Embed mode.
- `max_response_size`.
- SSRF-safe `resolve=` DNS pinning.
- Reddit anonymous-session bootstrap.

## 0.2.x - 2026-04-05 to 2026-06-07

- Moved from rnet to wreq.
- Dart 3.11 profile.
- Native-TLS fallback for Imperva.

## 0.1.x - 2026-02-23 to 2026-03-06

- First releases: TLS fingerprinting on rnet, cookie caching, retries and
  rotation.
- Challenge detection and solvers for Cloudflare, DataDome, Kasada, Akamai,
  PerimeterX, F5 Shape, reCAPTCHA and hCaptcha.
- Safari 26 profile.
- The Mousse labeling tool.
