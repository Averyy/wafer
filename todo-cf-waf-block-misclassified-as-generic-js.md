# TODO: Cloudflare WAF *block* pages are classified as `generic_js`

**Status:** RESOLVED (2026-07-29)
**Reported by:** fetchaller-mcp (2026-07-28)
**wafer version tested:** 0.4.1
**Repro host:** `https://airmatrix.ca/`

## Summary

A Cloudflare **WAF rule block** (Error 1020 -"Sorry, you have been blocked")
is being reported as `challenge_type="generic_js"`. It is not a challenge:
there is nothing to solve, and no amount of retrying, identity rotation, or
browser solving can change the outcome. Callers currently treat it as a
transient, solvable state and burn their whole rotation budget on it.

## Reproduction

```python
import wafer  # 0.4.1

with wafer.SyncSession(max_rotations=4, max_retries=3) as s:
    s.get("https://airmatrix.ca/", timeout=60)
# wafer.ChallengeDetected: generic_js challenge detected at https://airmatrix.ca/ (HTTP 403)
```

Three consecutive attempts, each returning in **0.1 s**. The speed is itself a
signal -nothing was solved or even attempted.

## Evidence that this is a block, not a challenge

Fetched with `max_rotations=0, max_retries=0`:

| Property | Value |
|---|---|
| Status | `403` |
| `server` | `cloudflare` |
| Body size | 4,907 bytes |
| `<title>` | `Attention Required! | Cloudflare` |
| `<h1>` | `Sorry, you have been blocked` |
| `<h2>` | `You are unable to access airmatrix.ca` |
| Body text | "This website is using a security service to protect itself from online attacks. The action you just performed triggered the security solution." |
| `/cdn-cgi/styles/cf.errors.css` | **present** |
| `/cdn-cgi/challenge-platform` | **absent** |
| Turnstile / `jsd` | **absent** |

The distinguishing marker is the pair: `cf.errors.css` present **and**
`challenge-platform` absent. A real interstitial (managed challenge, JS
challenge, Turnstile) always loads `/cdn-cgi/challenge-platform/...`. This page
loads the static Cloudflare *error* stylesheet and ships no challenge script,
because there is no challenge -the request matched a WAF rule and was denied.

## Resolution -the classification

Implemented exactly as proposed, using the marker pair above.

- `ChallengeType.CLOUDFLARE_BLOCK` (`"cloudflare_block"`), gated on HTTP 403 so
  a 1015 rate-limit page keeps the existing 429 / `Retry-After` path.
- `TERMINAL_CHALLENGES` in `wafer/_challenge.py` -the set that never reaches
  the retry, rotation, or browser-solve paths. It is checked before the session
  records a domain failure, so a block also cannot retire a session identity
  that was never the reason for the denial.
- `wafer.RequestBlocked`, a subclass of `ChallengeDetected`. Existing
  `except ChallengeDetected` handlers keep working; catching it separately
  distinguishes "try again later" from "this will never work as-is". Its
  message says so outright. Under `max_rotations=0` the block is returned as a
  response with `challenge_type="cloudflare_block"`, matching how every other
  challenge behaves in that mode.

Measured after the fix, same call as the repro above:

```
RequestBlocked in 0.07s
  cloudflare_block blocked the request to https://airmatrix.ca/ (HTTP 403);
  a WAF rule denied it, so retrying, rotating identity, and browser solving
  all return the same answer
  rotations: 0 | retries: 0
```

Tests: `tests/test_challenge.py::TestCloudflareBlock` (against a captured copy
of the live page, `tests/fixtures/cloudflare_waf_block_1020.html`) and
`tests/test_retry.py::TestSyncTerminalBlock` / `TestAsyncTerminalBlock`. The
discriminator is guarded in both directions -a body carrying
`challenge-platform` or `_cf_chl_opt` is never classified as terminal, and
`miata.net` was re-verified live as a solvable `cloudflare` challenge.

## Secondary: the block itself -measured, not fixable here

The report was right to separate the two problems. On (2), "the request was
blocked at all", the measurements do not support a wafer-side cause:

| Client | Result |
|---|---|
| wafer / wreq Chrome149 | 403, 1020 block page |
| Real headed Chrome 150 (the browser solver, full fingerprint patches) | 403, identical block page |
| `curl`, default UA | 403 |
| `curl`, Chrome UA + full navigation header set, HTTP/2 | 403 |
| check-host.net nodes in Poland, Romania, Slovenia, Ukraine | 403 on all four |

A genuine Chrome binary is denied identically, and four unrelated networks in
four countries get the same 403. The rule cannot be keyed on TLS/JA3/JA4, H2
settings, header order, or this egress address; `airmatrix.ca` is denying
essentially all comers. Nothing wafer can vary changes the answer, which is why
the terminal classification is the whole fix available here.

**Resolved by the reporter (2026-07-29): `airmatrix.ca` is not the live site.**
The company's real domain is `airmatrix.ai`, which wafer fetches at 200 (78KB,
5,083 chars of visible text, no challenge, no render needed). The two are
separate Cloudflare zones on different nameserver pairs; `.ca` has no live
origin behind it. A parked zone denying all traffic with a WAF rule is exactly
what the measurements showed, and it is the site owner's intent rather than
anything wafer can route around -which is what makes the terminal
classification the correct and complete fix here.

`airmatrix.ca` is kept in `docs/site-list.md` as the live regression target for
`cloudflare_block`.

## Out of scope for fetchaller

Per the fetchaller/wafer boundary, fetchaller does no challenge classification
and will not parse challenge bodies. It only reports whatever
`challenge_type` wafer hands it, so this had to be fixed here to be fixed at all.
`"cloudflare_block"` is now a value it can surface and act on: for that type the
"a retry sometimes helps" advice is wrong and should be suppressed.
