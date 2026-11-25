# Cloudflare: blocks, the JS-detections beacon, and page Turnstile

This covers what wafer reads as a Cloudflare *block* (`cloudflare_block`) as opposed to a
solvable interstitial (`cloudflare`), and the one case where a block is cleared. The
interstitial solver itself is `wafer/browser/_cloudflare.py::wait_for_cloudflare`.

## Block or challenge

Cloudflare serves its error stylesheet `/cdn-cgi/styles/cf.errors.css` on every error page.
A challenge also loads the challenge platform (`/cdn-cgi/challenge-platform/h/.../orchestrate/...`)
or carries `cf_chl` markers; a block (Error 1020, the 100x IP bans, "Sorry, you have been
blocked") has neither. That pair is the discriminator in `detect_challenge`, at 403 only
(a 429 error page is rate limiting, which a clock clears).

### The JS-detections beacon is not a challenge

A zone with JS detections on (Bot Fight Mode, Bot Management) injects this into every HTML
document it serves, **its own block page included**:

```
var u='/cdn-cgi/challenge-platform/scripts/jsd/main.js?ray=...'
```

It is telemetry; it runs no challenge and clears nothing. Before 2026-11-24 any
`challenge-platform` string counted as "loads a challenge", so a block page carrying the
beacon fell through to `generic_js`, and callers were told a retry might help (a zone's
`/api/*`, wafer 0.7.15). The same string test made the browser
reject a real page under the 10 KB scan window as a challenge left in place.
`loads_cf_challenge_platform()` in `wafer/_challenge.py` is the one check, used by
`detect_challenge`, `_is_passthrough_challenge_html` and `_page_is_challenge`; it matches
`challenge-platform` anywhere except as `challenge-platform/scripts/jsd/`. The captured block
page is `tests/fixtures/cloudflare_waf_block_jsd_2026-11-24.html` (visitor IP replaced with
`192.0.2.1`).

### Cloudflare's injected scripts do not make a 403 a JS challenge

The generic-JS fallback (403/429, a `<script`, under 50 KB) took any script for a challenge's.
Cloudflare injects scripts into every document it proxies, whatever the origin sent: the
JS-detections loader (an inline IIFE that sets `window.__CF$cv$params` and loads the beacon
above), the Web Analytics beacon (`static.cloudflareinsights.com/beacon.min.js`), and
`/cdn-cgi/scripts/` helpers (email obfuscation, Rocket Loader). An origin answering a missing
session with Werkzeug's stock 403 (1,685 bytes) carries only the first two, and that read as
`generic_js`: a browser solve on the URL itself, rotations, a retired session, and "try again"
(fetchaller, 2026-11-24). `has_page_script()` counts only
the document's own scripts; an unclosed or unrecognized `<script` still counts. Fixture:
`tests/fixtures/cloudflare_origin_403_2026-11-24.html`.

## A block the site's own page clears

A block is usually final, and wafer spends no retry or rotation on it. But the rule behind
it can key on state the site's own pages set: a Cloudflare zone whose own pages run Turnstile
and whose `/api/*` routes need the session cookie that sets (seen 2026-11-24):

1. `/api/*` answers every request without the site's `session` cookie with the block page.
   The site's HTML pages answer 200.
2. Those pages carry the sitekey in an inline config and a site script that, once the page
   has loaded, loads `challenges.cloudflare.com/turnstile/v0/api.js?render=explicit` and
   renders the widget with `appearance: 'interaction-only'`, `execution: 'execute'`. In a
   hardened headless browser it passes with no click.
3. The widget's callback POSTs the token to a verify route on the site, which sets `session`
   (HttpOnly, host-only). Turnstile's pre-clearance sets `cf_clearance` on the registrable
   domain as well.
4. `/api/*` then answers 200.

Replayed over plain wafer: `session` alone gets 200; the `cf_clearance` the widget sets stays
blocked; `embed="xhr"` with the page as Referer stays blocked. A browser sent to the `/api` URL
itself gets the block page and nothing to solve.

The same missing session can come back from the origin instead. fetchaller's cache held a
`cf_clearance` scoped to the registrable domain, expiring a year out, earned on another of the
site's subdomains. With it, the edge lets `/api/*` through, and the origin answers its own 403
(see above), which the site's own client code also answers by running Turnstile. A browser
carrying that cookie would send it too: this is cookie scoping working, not a stale jar.

### What wafer does

A *Turnstile refusal* is a `cloudflare_block`, or an origin's 403 behind Cloudflare (a `cf-ray`
header, an HTML or untyped body, no challenge detected: `is_cloudflare_origin_refusal`). With a
`browser_solver`, one on a request that names a page on the same registrable domain gets one
recovery (`_turnstile_recovery_page` in `wafer/_base.py`). The page is `solve_origin`, else
the request's `Referer`, else `Origin`, else `embed_origin` (`_caller_page`); never another
site's page (its cookies never reach the URL) and never the refused URL.

The page check and the solve are requests the caller did not make, to a host a
caller-controlled header named, so `_turnstile_page_target` keeps them inside the caller's
own guards: the refused URL's registrable domain, scheme and port, and with `resolve=` set
only a host the map pins. What is checked is what is sent: the URL is rebuilt from the parts
that passed, and anything a WHATWG parser (wreq's, Chrome's) could read differently from
`urlsplit` is refused: backslashes (`http://127.0.0.1:8080\@www.example.org/` is
www.example.org to `urlsplit` and 127.0.0.1:8080 to a browser), userinfo, whitespace and
control characters, non-ASCII, hosts outside `[a-z0-9.-]` (IPv6 literals included), and an
explicit port 0. An unpinned same-site name would go to system DNS, and a
`Referer: http://internal.<zone>:8080/` resolving to a private address was a blind GET from
wafer (fetchaller's review, 2026-11-24, reproduced on loopback; fetchaller pins every host it
validated and runs `follow_redirects=False`). `_turnstile_page_redirects` follows no
redirect when the session follows none, else up to three within `max_redirects`, and each hop
passes `_turnstile_page_target` or the check ends with no.

1. The page is fetched over HTTP first (`_page_runs_turnstile`, redirects as above, 2 MB,
   15 s within the request's budget, through the rate limiter, DNS pins and cookie-scope
   bookkeeping like any request). Only a 2xx page whose document names Turnstile
   (`page_runs_turnstile`: a `0x4AAAAAA` sitekey, `cf-turnstile`, or challenges.cloudflare.com
   in the body) gets the browser. The pages measured carry the sitekey inline; the api.js URL
   itself is only in a separate site script (`/static/turnstile.js`). A real ban costs this
   fetch, not a browser visit: the page is refused too.

   The CSP alone does not count. The measured zone sends the same CSP, naming
   challenges.cloudflare.com in `script-src` and `frame-src`, on every page. Its home page
   (170 KB, no sitekey, no `cf-turnstile`, no "turnstile" anywhere in the body) has no widget:
   in 0.7.17, where the CSP answered on its own, a refused `/api` call with the home page as
   Referer passed the check, spent a browser solve on it, saw no widget in 8 s, and stayed
   blocked after 11 s (fetchaller 3.8.16, 2026-11-25). The CSP still counts together with the
   word "turnstile" in the document, for a page whose widget script also holds the sitekey.
   No live page has needed that case yet: the widget pages measured carry the sitekey inline.
   The body is always read, up to 2 MB; a longer page is judged on its first 2 MB (it used
   to count as no).
2. One browser solve on the page (challenge type `cloudflare_block`, below), keyed per request
   on the URL's host for both kinds of refusal, so a request that turns from one into the other
   is not solved twice.
3. The retry. What it gets stands: a surviving block raises `RequestBlocked` (or is returned
   under `max_rotations=0`); a surviving origin 403 takes the usual 403 path.

A page that shows no Turnstile, or whose recovery did not clear the refusal (solve False, or
the retry refused again), goes into the session's `_turnstile_page_misses` and is not used
again for `_TURNSTILE_PAGE_RETRY_SECONDS` (600 s): a refusal that is the site's real answer
costs one page fetch per window.

One kind of miss is also shared on the browser solver (`_turnstile_shared_misses`): a solve
that passed while the retry was still refused. Every session sharing the solver skips that
page, so a caller that builds a session per fetch around one solver (fetchaller) pays for it
once per window too. Sessions that share a solver share its proxy, so that miss means the same
for each. The store (`_TURNSTILE_MISSES_BY_SOLVER`) is keyed by the solver's identity through
a weak reference, so it goes with the solver, and two solvers that compare equal are still
two. A solver that cannot be weakly referenced shares nothing. A page that showed no Turnstile,
or a solve that failed or timed out, stays with the session (Avery, 2026-11-25): in
fetchaller's Linux image a solve can time out under host CPU load, and a shared timeout would
have every fetch skip the right page for the rest of the window after the load dropped. A
failed solve also clears the request's record of the page, so the request's next refusal is
not read as a solve that passed. Entries past the window are dropped on the next miss. The
solve's cookies go through `defer_cache`, so a failed recovery
persists nothing to `cache_dir`. With no such page, or no browser, a block is raised on the
first response and an origin 403 is an ordinary 403.

In the solver, challenge type `cloudflare_block` dispatches to `wait_for_page_turnstile`:

- The page's main document answered >= 400: nothing to solve, return False at once.
- Wait for a `challenges.cloudflare.com` frame. The grace (`_PAGE_WIDGET_GRACE_SECONDS`, 8s)
  runs from `document.readyState == "complete"`, not from DOMContentLoaded: the measured
  widget came up 7.4s after DOMContentLoaded on a Mac, because the page loads api.js only
  after `load`. A page that never finishes loading starts the grace after
  `_PAGE_LOAD_CAP_SECONDS` (20s).
- Done when the page's own cookie for its host changes in a way only the page's answer
  explains (Cloudflare's `cf_clearance`, `__cf_bm`, `_cfuvid`, `cf_chl*` never count:
  pre-clearance sets `cf_clearance` before the page has used its token):
  - an HttpOnly cookie a response set at any point in the solve. A script cannot set one, so
    it is checked first and needs no widget sighting: a widget that passes at once can be
    removed by the page before a poll sees it. The measured site's `session` is HttpOnly.
  - with a readable token field (`cf-turnstile-response`), any change after the token, so a
    cookie another script sets meanwhile (analytics) is not taken for the answer; a token
    with no cookie of the page's own within `_PAGE_TOKEN_SETTLE_SECONDS` (8s) ends the wait
    too (a rule keyed on `cf_clearance` needs nothing more). On the measured site the field
    was **not** readable from the page's DOM.
  - without a readable field, any change since the poll *before* the widget was seen, so a
    cookie set in the same 0.5s interval the widget appeared in is not swallowed into the
    baseline.
- Every wait inside the loop (a click, a browse chunk, the settle after the answer) is clamped
  to the solve's deadline.
- An interaction-only widget has no size until it asks for a click; it is clicked (every
  5s) only once it has one.

Live, 2026-11-24, macOS, wafer working tree, against the zone described above:
- Cold `AsyncSession(browser_solver=...)`, an `/api` GET with a widget page as Referer: 200
  in 25.8 s (one browser launch, one page load, widget 7.4 s after DOMContentLoaded,
  `session` 2.2 s after the widget); 6.0 s on a later run.
- `SyncSession`, another widget page as Referer: 6.5 s; then an `/api` call with no Referer
  over plain HTTP, 200 in 0.4 s.
- A `cache_dir` holding only the other subdomain's `cf_clearance`: the origin's 403, the page
  check ("runs Turnstile"), one solve, 200 in 6.5 s and 6.4 s.
- airmatrix.ca with a same-site Referer: `RequestBlocked` in 1.9 s (measured before the page
  check existed; the page answered 403, so the solver stopped at once).
- Through fetchaller's own MCP server, empty cache: no Referer, `cloudflare_block` in 2.5 s;
  a widget page as Referer, JSON in 4.5 s; a new process on that cache, 200 in 0.9 s with no
  browser (`session`, about 24 h, persisted). A copy of its real cache (the other
  subdomain's cookie): no Referer, a plain 403 after the usual 403 handling, no browser;
  widget page as Referer, JSON in 5.0 s.

Linux, 2026-11-24, fetchaller's linux/amd64 image (Chrome for Testing 158 under Xvfb,
amd64 emulated on Apple Silicon), the same request:
- On a quiet host (load about 3), 4 of 4 passed: the candidate at 16.0, 20.3 and 21.5 s,
  and published 0.7.16 at 22.4 s. Each time the widget came up as the 1x1 interaction-only
  frame about 3 s after the solve started, and the session cookie followed about 6 s later,
  with no click.
- Two earlier image runs that timed out at about 115 s (one on 0.7.16) were made while the
  host was saturated (load average up to 116). With the image's 6 vCPUs deliberately
  saturated (24 busy loops), the solve failed the same way: widget up, no session cookie,
  `RequestBlocked` at 85 s. The page itself had given up on its verification within the first
  seconds and offered a retry, so a browser on that starved host fails too. Emulated amd64
  Chrome is several times slower than native, so a timing verdict from the image needs a
  quiet host (check `uptime` first).

### Not done

- No page is guessed for a request that names none. Which page carries the widget is the
  site's business; the caller says which page makes the call, as a browser would.
- A block whose rule keys on something a page sets other than a cookie (a header from
  localStorage, a token in the request body) cannot be carried over HTTP; the retry stays
  blocked and the block is raised.
