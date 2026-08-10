# Radware Bot Manager Solver

Radware Bot Manager is the product formerly sold as ShieldSquare. Its edge runs
under `perfdrive.com`, and protected origins are usually CNAME'd to
`*.radwarecloud.net`.

## Status

**Detection**: Done, on two signals in `wafer/_challenge.py` -
`is_radware_challenge` (body, status-agnostic) for the captcha page, and
`is_radware_challenge_redirect` (`Location` header) for the 3xx that fronts it.

**Solving**: Done, inline. No browser, no CAPTCHA solve.

| Challenge | Status | How |
|---|---|---|
| Captcha interstitial (hCaptcha widget) | **Works** | The redirect that fronts it issues the clearance. Replay the original URL on the same session. |
| The fronting 302, seen with `follow_redirects=False` | **Works** | Detected by its `Location` host; replayed without ever fetching the captcha. |
| Hard denial (no clearance issued) | **Detect-only** | Raises `ChallengeDetected("radware")`. Nothing was handed over to replay. |

The hCaptcha widget embedded in the interstitial never has to be touched. The
block clears before it matters.

## The exchange

Measured against `www.gojobs.gov.on.ca` (Ontario Public Service Careers), which
is CNAME'd to `0340c5d1993946d599139100a2a8b66f.v1.radwarecloud.net`.

```
GET https://www.gojobs.gov.on.ca/Preview.aspx?JobID=232882
  -> 302  Set-Cookie: __uzma, __uzmb, __uzmc, __uzmd, __uzme, __uzmf   <- the clearance
     Location: https://validate.perfdrive.com/?ssa=...&ssc=<original url>...

GET https://validate.perfdrive.com/?ssa=...
  -> 200  15,066 bytes  <title>Radware Captcha Page</title>            <- the block

GET https://www.gojobs.gov.on.ca/Preview.aspx?JobID=232882   (same jar)
  -> 200  84,984 bytes  <title>Ontario Public Service Careers - Job Preview</title>
```

Two properties of that exchange drive the whole design:

1. **The block is an HTTP 200.** No error, no non-2xx status, no exception. A
   caller that only checks `status_code` renders the "we think that you are a
   bot" page as though it were the article.
2. **The origin, not the captcha host, issues the clearance.** The 302 sets the
   `__uzm*` family on `www.gojobs.gov.on.ca` before anything redirects.
   `validate.perfdrive.com` then sets a `__uzm*` family of its **own**, which is
   a different and useless one.

## Detection

The trap here is the same one Imperva's `_Incapsula_Resource` sets. Radware's
sensor rides on ordinary pages of a protected site, so the obvious signals do
not separate a block from real content. Measured on the same URL, block page vs
the real job page served moments later:

| marker | block | real page |
|---|---|---|
| `SSJSConnectorObj` (sensor bootstrap) | yes | **yes** |
| `__uzdbm_*` globals | yes | **yes** |
| `__uzm*` Set-Cookie | yes | **yes** (`__uzmc`, `__uzmd`, `__uzmf`) |
| `captcha.perfdrive.com` | yes | no |
| `shieldsquare` (stylesheet filename) | yes | no |
| `SSJSInternal` | yes | no |
| `Radware Captcha Page` (title) | yes | no |
| `aperture.js` absolute URL | yes | no |

So detection requires **both** halves: a sensor marker AND a captcha-template
marker. Keying on the cookie family, or on `SSJSConnectorObj` alone, re-flags
every page the site serves and spins the retry loop forever. Keying on a
template string alone would fire on any page that merely writes about the
vendor.

Detection runs on any status code and is ordered ahead of the 403/429 block in
`detect_challenge`, so a deployment that serves the interstitial as 403 is not
swallowed by the `generic_js` fallback.

`tests/fixtures/radware_gojobs_captcha.html` and
`radware_gojobs_real_page.html` are the two captures above. The real page is a
fixture precisely because it is the false positive worth guarding against.

Both were scrubbed before being committed, and anything captured from a live
site must be. Radware encodes the requesting client's IP into the `__uzdbm_2`
global as base64 of `<uuid>$<ip>`, so a verbatim capture publishes the
capturing host's address to PyPI. The visitor UUIDs were replaced with
placeholders, the IP with `192.0.2.1` (RFC 5737), and the real page's captured
ASP.NET `__VIEWSTATE` / `__EVENTVALIDATION` blobs were redacted - opaque server
state that marker testing does not need and that is pure publication risk.
`tests/test_challenge.py` asserts detection is unchanged by all of it.

## Solving

`_try_inline_solve` handles `ChallengeType.RADWARE` with no sub-request at all.
The interstitial already banked the clearance; the solve is to replay.

Two details are load-bearing:

- **The clearance is looked up against the ORIGIN, not the challenged URL.** By
  the time the captcha page is in hand, the retry loop has followed the
  redirect and `current_url` is `validate.perfdrive.com`. Checking that host's
  cookies finds a `__uzm*` family and reports a clearance the origin never got.
  `_try_inline_solve` takes `origin_url` for this reason.
- **The loop rewinds to the caller's request, and does it before anything else
  reads that state.** After the redirect the loop is parked on the captcha page;
  replaying *that* just re-serves the captcha. The rewind runs at the top of
  challenge handling, not only on a successful solve, so a declined solve also
  rotates against the origin and the raised `ChallengeDetected` names the URL
  the caller asked for rather than validate.perfdrive.com.
- **The rewind restores the request, not just the URL.** Following a 301/302/303
  downgrades a POST to GET, drops the body, and strips sensitive headers - right
  for a real redirect, wrong for a challenge hop. Without restoring `method`,
  the body kwargs and the header set, a caller's POST came back as a bodyless
  GET *and still returned 200*, which reads as success. The hop to Radware's
  host keeps the RFC behaviour: it carries no body and no `Authorization`, so
  credentials never reach the WAF - only the origin replay gets them back.

`_radware_clearance_cookies()` reads the jar rather than assuming, so an
interstitial that hands over nothing is not counted as solved - that request
falls through to rotation and ends as an honest `ChallengeDetected`. It counts
only cookies the replay would actually send: host-suffix, Path and Secure are
all checked, because a `__uzm*` scoped elsewhere is never transmitted and
crediting it would claim a clearance the origin will not see. wreq strips the
leading dot from every Domain, so host-only and Domain cookies cannot be told
apart here; the match errs permissive and the cost is one wasted replay.

Existence alone is not enough, though. A deployment whose clearance does not
work re-serves the block with the **same** `__uzm*` values, and those cookies
are still sitting in the jar on the next pass, so an existence check would call
it solved every time and spend the whole inline budget on replays that cannot
differ. `_radware_clearance_fingerprint()` records what each replay rode on and
the solve is refused when the clearance comes back unchanged: 3 requests to fail
instead of 5. A clearance that genuinely rotates still earns another attempt,
which matters because gojobs needed two rounds in one live run.

Detection is on the hot path for every response wafer handles, so the body test
reuses the single `body_lower` that `detect_challenge` already computes
(`_matches_radware_markers`). Lowercasing an 85KB body twice cost ~0.14ms per
response; `detect_challenge` on the real gojobs page went 0.62ms -> 0.48ms. The
public `is_radware_challenge()` still takes a raw body and lowercases it, so an
external caller cannot silently get case-sensitive matching.

Radware is deliberately **not** in `JS_ONLY_CHALLENGES`. Listing it would make a
browser-less session raise `ChallengeDetected` before the free replay ever ran.

In practice the origin may re-serve the interstitial once before letting the
session through; `max_inline_solves` (3) covers that.

## Not the IP

Radware's block copy blames "an anonymous Private/Proxy network" and
"previously detected malicious behavior which originated from the network
you're using". On a residential line hitting a provincial government site,
neither applies, and the replay clearing from that same IP seconds later
disproves it directly. Treat the copy as boilerplate.

## Live verification

2026-08-10, `www.gojobs.gov.on.ca` from a residential connection, wafer with no
browser solver configured:

| path | result |
|---|---|
| `wafer.get()` cold session, `/Preview.aspx?JobID=232882` | 200, 84,984 bytes, `Ontario Public Service Careers - Job Preview`, `challenge_type` None, `__VIEWSTATE` + `aspnetForm` present |
| `AsyncSession.get()` same URL | 200, 84,984 bytes, same title |
| warm `SyncSession`, 3 sequential pages (`Preview`, `JobsAlert`, `Search`) | 200 / 200 / 200, real content each, no re-detection |

`JobID=232882` is a live posting and will eventually close. If that URL starts
failing while `/Search.aspx` still passes, swap in a current ID rather than
reading it as a change in Radware's behaviour.

**The block is reputation-gated, not deterministic.** After the runs above,
gojobs stopped challenging this egress entirely -cold sessions began returning
the real page on the first request, with no interstitial to solve. So "I cannot
reproduce the block" is the expected state once a client has built standing, and
is not evidence the solver regressed. To exercise the challenge path again, come
from an egress that has not been seen recently. The fixtures exist so the
detection half stays testable regardless.

## `follow_redirects=False`

A caller that walks the chain itself never reaches the captcha page - it sees
only the origin's 302. That hop is detected on its own signal: a 3xx whose
`Location` host is under `perfdrive.com`. Nothing else is safe to key on there,
because the sensor globals and the `__uzm*` cookies ride on ordinary responses
from the same edge, and `server: rdwr` is on every response the edge serves.

This case is strictly cheaper than the default one. The 302 already carries the
clearance, so wafer replays the original URL straight from it and **never
contacts `validate.perfdrive.com` at all**. Verified live: one cold
`follow_redirects=False` session, two requests, 200 with the real job page.

Ordinary redirects are untouched - a 302 to any non-Radware host is returned to
the caller as a 302, exactly as it was before.

Matching is deliberately narrow. Only `http`/`https` count, so a `Location` on
some other scheme is never treated as a challenge. Host matching is
boundary-aware: `perfdrive.com` and its subdomains match, `evil-perfdrive.com`
and `perfdrive.com.evil.test` do not. `urlparse` resolves userinfo to the real
destination, so `https://validate.perfdrive.com@evil.example/` has hostname
`evil.example` and is rejected - which is the direction that matters, since the
converse genuinely does land on Radware's host.

Because wafer only ever re-requests the URL the caller already asked for, and
never follows the hop into Radware's host, this does not widen what a
per-hop-validating caller (SSRF pinning, allowlists) is exposed to.

## Cross-deployment checks

Detection was exercised against four distinct Radware tenants on 2026-08-10.
Only gojobs served a block; the others are what prove the detector stays quiet
on a vendor whose sensor is everywhere:

| host | response | vendor markers | detected |
|---|---|---|---|
| `gojobs.gov.on.ca` | 200 captcha, and the 302 fronting it | all | **yes**, correctly |
| `sos.state.mn.us` | 200 real homepage | sensor, `__uzm*`, stormcaster, perfdrive | no, correctly |
| `sedarplus.ca` | 200 real landing page | sensor, `__uzm*`, stormcaster, perfdrive | no, correctly |
| `sedarplus.ca` | 301 to its own host, `server: rdwr` | edge headers | no, correctly |
| `mndor.state.mn.us` | real 404 | sensor, `__uzm*`, stormcaster, perfdrive | no, correctly |

The sedarplus 301 is the reason `server: rdwr` is deliberately **not** part of
the redirect signal: the Radware edge stamps that header on ordinary redirects
too. Only the `Location` host separates a challenge hop from a normal one.

Radware's hCaptcha sitekey (`ae73173b-7003-44e0-bc87-654d0dab8b75`) and the
`stormcaster.js` path UUID are vendor-wide constants, not tenant identifiers -
the same values appear on unrelated deployments, including radware.com itself.

## Limits

- **The block-side markers are backed by one deployment.** Three other tenants
  were reached but none of them challenged, so only gojobs has exercised the
  captcha template and the fronting 302. A white-labeled deployment that serves
  the captcha from a customer domain instead of `perfdrive.com` would evade the
  redirect signal, and `SSJSInternal` plus the title would be carrying the body
  signal alone. Treat a new Radware site that fails as a marker-coverage
  question before anything else.
- Other Radware sites may serve a hard denial with no clearance, which is
  detected but not solvable.
- `Emulation.OkHttp5` reportedly passes this site on the first request with no
  cookies at all, where every browser identity is blocked. wafer does not use
  that: a per-site emulation pin reaches around identity selection and would rot
  the moment Radware rescores OkHttp. The inline replay costs one extra round
  trip per jar and does not depend on how the vendor scores any one client.
