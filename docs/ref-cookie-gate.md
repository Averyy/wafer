# Cookie Gate Solver

A site-owned interstitial whose inline script writes a fixed cookie and reloads,
usually from a "Continue" button. Nothing is computed, so wafer writes the same
cookie and replays. Measured 2026-09-26 on `fccid.io` (`fcc_continue`) and
`fcc.report` (`fcc_report_continue`), both behind a Cloudflare managed
challenge.

## Status

**Detection**: `is_cookie_gate` in `wafer/_solvers.py`, called from
`wafer/_challenge.py` on any status (`ChallengeType.COOKIE_GATE`, `"cookie_gate"`).
Structural: the body is at most 20 KB, and one inline script writes only string
literals to `document.cookie` and then calls `location.reload()`. A script that
computes any part of a cookie is not this gate. Prose that quotes the script has
no script element around it, and a real document fails the size cap. This file
is a negative control in `tests/test_challenge.py`.

**Solving**: inline, in `solve_cookie_gate`. No browser.

| Case | Status | How |
|---|---|---|
| Gate page | **Works** | Write each cookie (name and value must be RFC 6265 tokens), replay on the same jar. |
| Cookie with `Max-Age` | **Works** | Persisted to the cookie cache for that lifetime, capped at a day. |
| Cookie with `Domain` | **Works** | Honoured only when the request host is on it and it is at or below the registrable domain, as for the PoW gate; otherwise host-only. |
| Computed or malformed cookie | **Not detected** | The page is returned as it came. |
| Gate re-served after a solve | **Detect-only** | Bounded by the inline-solve cap; raises `ChallengeDetected("cookie_gate")`. |

## The exchange

```
GET https://fccid.io/2AC7Z-ESPWROOM32
  -> 403  Cloudflare managed challenge ("Security check | FCC ID" template)
     (headless browser solve; the whole request took 4.1 s)
  -> 200  2,428 bytes  <title>Security check | FCC ID</title>
     one button, id="continue"; its click handler runs:
       document.cookie="fcc_continue=1; Path=/; Max-Age=1800; Secure; SameSite=Lax";
       location.reload();

GET https://fccid.io/2AC7Z-ESPWROOM32   (same jar + fcc_continue=1)
  -> 200  72,092 bytes  <title>FCC ID 2AC7Z-ESPWROOM32 - Wi-Fi &amp; Bluetooth Module</title>
```

`fcc.report` serves the same gate with its own cookie, then answers the
original URL with a 301 to fccid.io. With redirects followed, the request takes
one browser solve per host and both gates inline (7.3 s measured).

## Browser interplay

When a browser solve lands on the gate, the solver treats it as still a
challenge (`_is_passthrough_challenge_html`) and returns cookies only. The
session replays over wreq, meets the gate, and solves it inline. Once the
cookie expires the gate returns, and it is solved inline again without the
browser.
