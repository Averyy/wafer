# Proof-of-Work Gate Solver

A home-grown, vendor-less bot gate: the origin (fronted by Varnish / Fastly)
answers every page with a SHA-256 puzzle and lets the request through once a
cookie proves the puzzle was solved. Measured on `redflagdeals.com`, on both
`www.redflagdeals.com` and `forums.redflagdeals.com` (phpBB). No third-party
script, no CAPTCHA, no sensor -pure computation, then set a cookie and replay.
It is the ACW shape with a hash loop in place of ACW's shuffle.

## Status

**Detection**: Done, `is_pow_challenge` in `wafer/_solvers.py`, called from
`wafer/_challenge.py` on any status code. Structural: body under 50 KB, the
`POW_CHALLENGE_DATA` object opened inside a `<script>` element, and the
`pow_bypass` name (required because it is the cookie the solver writes; a
variant naming its cookie differently must not be "solved" with the wrong
one). Nothing else about the script's text is assumed, so an obfuscation pass
cannot silently turn the gate back into content. A page that only quotes the
object (a bug report, this file, an HTML-rendered doc with escaped tags) is
not detected, and a real document that embeds all of it fails the size cap.
`tests/test_challenge.py` feeds this very file to the detector as a negative
control.

**Solving**: Done, inline, in `wafer/_solvers.py` (`solve_pow`). No browser.

| Challenge | Status | How |
|---|---|---|
| The 202 puzzle page | **Works** | Read the data object, run the hash loop, write `pow_bypass`, replay on the same jar. |
| Malformed data object | **Detect-only** | Refused rather than guessed; the loop falls through to rotation and finally `ChallengeDetected("pow")`. |
| Gate re-served after a solve | **Detect-only** | Bounded by the inline-solve cap; raises `ChallengeDetected("pow")` instead of returning the script page. |

## The exchange

Measured 2026-09-07 with wafer on a residential connection.

```
GET https://forums.redflagdeals.com/viewtopic.php?t=2789391
  -> 202  2,671 bytes  text/html
     server: Varnish          retry-after: 0
     cache-control: no-store, private
     set-cookie: pow_trace=<nonce>|<issued_at>; domain=.redflagdeals.com;
                 path=/; max-age=86400; SameSite=Lax; Secure

  (solve: 90 SHA-256 calls for this nonce, well under a millisecond)

GET https://forums.redflagdeals.com/viewtopic.php?t=2789391   (same jar + pow_bypass)
  -> 200  179,974 bytes  <title>[Best Buy] [Black Friday] Bose QuietComfort ... - RedFlagDeals.com Forum</title>

GET https://www.redflagdeals.com/                             (same jar, no new solve)
  -> 200  528,163 bytes  <title>Canadian Deals, Flyers & Coupons - RedFlagDeals.com</title>
```

The gate is host-wide with `/feed/*` and `robots.txt` exempt. Every other path
on both hosts returns the same 202 with a fresh nonce per request.

## Why this needed a body check

The page is a clean HTTP 202. Nothing about it is an error to a status-based
check, and the body, once the `<script>` and `<noscript>` are stripped, is
empty. Before this solver landed, `detect_challenge` returned `None`: the
generic-JS arm would have caught it (small body, script present) but that arm
is gated to 403/429, and this site never sends either. Consumers then rendered
the script page as an empty document and read that as "the site is
JavaScript-gated". The status is therefore deliberately NOT part of the
detection: the data object is the marker.

## The puzzle

The page body is a `<head>` with one inline script and a `<noscript>`. The
script starts with the data object:

```js
window.POW_CHALLENGE_DATA={
    challenge_nonce:'e68a8b5e136aad05bdb6de05fbe2db98',
    challenge_hmac:'ba7e6328f78b8507c9141730',
    difficulty:'2',
    difficulty_char:'b',
    issued_at:'1788821011',
    cookie_duration:'3600',
    cookie_domain:'.redflagdeals.com',
    referrer:'(null)',
    headless_check:'1'
};
```

The script is not obfuscated. Its cookie write, verbatim from the body
captured 2026-09-07 (the `pow_bypass` literal detection keys on is this one):

```js
document.cookie='pow_bypass='+d.challenge_nonce+'|'+d.issued_at+'|'+u+'|'+c+'|'+d.challenge_hmac+(sig?'|'+sig:'')+'; domain='+d.cookie_domain+'; path=/; max-age='+d.cookie_duration+'; SameSite=Lax; Secure';
```

and the whole loop, read out:

```
for i in 1, 2, 3, ... (ceiling 1e7):
    h = sha256_hex( challenge_nonce + issued_at + str(i) )
    if h.startswith( difficulty_char * int(difficulty) ):
        break

cookie  pow_bypass = nonce | issued_at | i | h | challenge_hmac [ | signals ]
        domain=<cookie_domain>; path=/; max-age=<cookie_duration>; SameSite=Lax; Secure

location.reload()
```

Details `solve_pow` mirrors, each verified against the live gate:

- **Plain concatenation, no separator**, order `nonce + issued_at + counter`,
  counter as decimal text starting at 1 (`while(i++<1e7)` yields 1 first).
  Lower-case hex digest, prefix comparison.
- **`difficulty` and `difficulty_char` are data, not constants.** Today `2`
  and `b`: 1 in 256 hashes, so ~256 SHA-256 calls expected. Both are read from
  the page. `difficulty` is capped at 5 nibbles. Measured ~3M SHA-256/s in
  Python here: 5 expects ~1M hashes (a third of a second) and the script's own
  1e7 ceiling fails fewer than 1 in 10,000 such solves, while 6 expects 16.8M,
  more than the ceiling, so it would spend the whole ceiling (~3 s) and then
  usually fail. `difficulty_char` must be one hex character, because a
  lower-case hex digest can never start with anything else. `challenge_nonce`
  and `challenge_hmac` must be 16 to 128 hex chars (real: 32 and 24), so a
  page cannot hand back a megabyte cookie or stretch the hash preimage.
- **`challenge_hmac` is opaque and echoed unchanged.** 24 hex chars, almost
  certainly a server MAC over `nonce|issued_at`; the pair cannot be minted
  locally. Solve against the values in the page just served.
- **Five fields, never six.** With `headless_check:'1'` the script appends a
  comma-joined signals field only when a probe fires (`navigator.webdriver`,
  missing WebGL, a touch-points mismatch on a mobile UA). A clean browser
  fires none and sends five fields with no trailing separator, so that is the
  only shape wafer produces.
- **Cookie scope.** The page names `cookie_domain` (`.redflagdeals.com`),
  which is what lets one solve cover both hosts. wafer honours it only when
  the request host is that domain or under it AND the domain is at or below
  the host's registrable domain (`registrable_domain` in `wafer/_cookies.py`).
  wreq's jar does NOT enforce a public-suffix boundary (measured: it accepts
  `Domain=co.uk` from `evil.co.uk`), so without that check a page on a shared
  suffix such as `github.io` could plant a cookie every sibling receives.
  Anything refused degrades to a host-only cookie, which the gate accepts.
  `Secure` is added only on https URLs.
- **Persistence.** The cookie lives `cookie_duration` seconds (3,600 today).
  It is saved to the cookie cache with that expiry, not as a session cookie,
  so with `cache_dir` a new process does not re-solve within the hour. A
  zero or missing duration falls back to 3,600 (a zero-lifetime cookie would
  expire before the reload that needs it), and it is capped at 86,400 so a
  page cannot pin a cookie in the cache for years. Cheap as the solve is, a
  cold request still costs one extra round trip.
- **`pow_trace` is not required.** The 202 sets it alongside `pow_bypass`.
  Measured 2026-09-07: a session with `cache_dir` solved on the forums host,
  its cache file held only `pow_bypass`, and a fresh session hydrated from
  that file fetched `www.redflagdeals.com` as 200 with no re-solve, never
  having held `pow_trace`. Within one session the replay keeps it anyway.
- **Deadline.** The hash loop checks the caller's remaining budget every 4,096
  hashes (well under a millisecond with the bounded preimage) and returns
  `None` when it is spent. Pure computation has no sub-request to clamp, but
  difficulty is the page's choice, so the work is not known to be trivial
  until the page has been read. `AsyncSession` runs the loop in a worker
  thread so a hard puzzle cannot stall the event loop.
- **Hostile bodies.** Only the first 50 KB are ever scanned, the object
  regex cannot backtrack across braces, and the `<script` attribute scan is
  bounded to 512 chars, so a body stuffed with unclosed `POW_CHALLENGE_DATA={`
  or with `<script` and no `>` costs bounded work per occurrence rather than
  the quadratic blow-up the naive `(.*?)}` form has (measured at 88 s for
  781 KB before this was fixed). The size cap is the backstop, not the only
  defence; do not raise it on the strength of the regexes alone.

## What was not varied

- **No other TLS identity was tried.** The gate hands every client the same
  puzzle and asks for work; it is not fingerprint-based on its face, so the
  rotation ladder was not spent against a site that rate-limits.
- **The IP is not the problem.** The page is not a denial: it issues a fresh
  nonce on every request and tells the client exactly how to pass.

## Testing

Unit tests in `tests/test_solvers.py` (`TestSolvePow`, the sync and async
`TestPowSolverIntegration*`) pin the measured vector: nonce
`e68a8b5e136aad05bdb6de05fbe2db98`, `issued_at` `1788821011`, counter 90,
digest `bbbc373e...99e3`. Detection tests are in `tests/test_challenge.py`
(`TestPow`).

Live check (one request at a time, 5+ s apart):

```python
import wafer
r = wafer.get("https://forums.redflagdeals.com/viewtopic.php?t=2789391", timeout=45)
assert r.status_code == 200
assert "POW_CHALLENGE_DATA" not in r.text
assert r.inline_solves == 1
```

Any live topic id works; the gate fires on the front page too.
