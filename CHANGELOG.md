# Changelog

All notable changes to wafer. Versions come from git tags (`hatch-vcs`); each
release is on [PyPI](https://pypi.org/project/wafer-py/) and
[GitHub Releases](https://github.com/Averyy/wafer/releases).

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
