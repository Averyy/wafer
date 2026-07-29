# RESOLVED: TMD challenge on Alibaba/AliExpress search URLs

**Status:** RESOLVED (2026-07-29)
**Reported by:** fetchaller-mcp (2026-07-29)
**Affected wafer versions:** 0.4.1 and 0.4.2
**Repro URL:** `https://www.alibaba.com/trade/search?SearchText=usb+c+cable`

## Resolution

Two bugs were involved:

1. The browser solver treated the exact application URL plus a missing Baxia
   iframe as clearance. Live inspection showed that state could still contain
   the 119KB `_____tmd_____` punishment DOM titled `Captcha Interception`, with
   no `x5sec`; all subsequent wreq replays remained challenged.
2. `session.render()` retried every status-200 document through a synthetic 403
   classification. Alibaba's legitimate page references `ips.js`, so it was
   misrouted to the Kasada solver and timed out.

The target predicate now requires the TMD marker to be absent from the main
document. A fresh target-scoped `x5sec` remains the only evidence used to claim
transport replay clearance. If Chrome reaches validated, challenge-free content
without a transferable cookie, wafer returns that exact GET as browser
passthrough without rebuilding or claiming future wreq requests are cleared.
Synthetic-403 render fallback is now limited to structurally recognized
interstitials.

Live verification against an actually triggered gate:

| Path | Result |
|---|---|
| `SyncSession(browser_solver=...)` | TMD on first request, first drag minted `x5sec`, replay returned 200 / 706,018 bytes in 21.05s |
| `session.render(url)` | TMD triggered and solved, returned 200 / 2,563,704 rendered bytes in 27.1s |

A bare `SyncSession.get()` has no browser solver and therefore still cannot
solve a persistent interactive slider by design. It can perform the inline TMD
warm-up; callers must configure `browser_solver=` for automatic solving or call
`session.render()` to create and use an owned solver.

## Original report

Alibaba's TMD (`_____tmd_____` / `x5sec` slide-verify) challenge is not being
passed on **search** URLs. This is **not a 0.4.2 regression** — 0.4.1 fails
identically — and it is **not caller-side**: a bare `wafer.SyncSession` with no
options reproduces it exactly.

The important detail is that it is **path-scoped, not domain-scoped**. The same
session, same identity, same minute:

| URL | Result |
|---|---|
| `alibaba.com/` (home) | 200, 190,868 bytes, real content |
| `alibaba.com/product-detail/...` | 200, 347,929 bytes, real content |
| `alibaba.com/trade/search?SearchText=...` | 200, **89,630 bytes — punish page** |
| `aliexpress.com/w/wholesale-...html` (search) | 200, **2,387 bytes — punish page** |

So the identity is not burned and the origin is not blocking the client. TMD is
gating the *search* endpoints specifically, on both properties.

## Reproduction

```python
import wafer
url = "https://www.alibaba.com/trade/search?SearchText=usb+c+cable"

with wafer.SyncSession() as s:
    s.get(url, timeout=60)
# wafer.ChallengeDetected: tmd challenge detected (HTTP 200)
```

| Path | Result |
|---|---|
| defaults (`max_rotations=2`) | raises `ChallengeDetected: tmd` — **6/6** |
| `max_rotations=0, max_retries=0` | returns the punish page — **6/6**, byte-identical 89,630 |
| `session.render(url)` (real browser) | `ChallengeDetected: tmd` after **74.8 s** |
| 0.4.1, defaults | identical failure |

The no-rotation 200 is not content: `punish`, `captcha`, `x5sec`,
`_____tmd_____`, `slide`, `verify`, and no `<title>`.

## Notable

1. **The browser path fails too.** `render()` drives a real Chrome and still
   ends at `ChallengeDetected`, after 74.8 seconds. Whatever TMD keys on is not
   cleared by a genuine browser navigation, so this does not look like a pure
   fingerprint problem.
2. **74.8 s to reach a known-terminal answer.** If TMD is not render-solvable,
   failing fast the way `cloudflare_block` now does would save the whole
   browser budget.
3. **Rotation does not help and may not be worth spending.** Both modes fail at
   the same rate; the only difference is wafer's documented raise-vs-return
   behaviour.
4. `needs_render=True` is set on the punish page. Literally true (the body does
   need JS) but it points at a remedy that does not work here — worth
   considering whether a body already classified as a challenge should suppress
   the render hint.
5. **Byte-identical 89,630-byte responses** across every attempt suggest a
   deterministic rule on the URL pattern rather than a scored/behavioural
   trigger.

## Intermittency (measured, then stopped)

The gate comes and goes, and both states last for tens of minutes:

- An early observation returned **1,441,219 bytes of real content** with
  `max_rotations=0`.
- Then 12 consecutive attempts across both modes returned the punish page,
  plus 8/8 failures through the calling application.
- Roughly an hour later the same search succeeded again through the full
  application path in **18.5 s** — no code change in between.

So this is an intermittent gate on the search path, not a permanent block, and
any fix should be validated across a window rather than a single run. Do not
read the successes as a mode difference; rotation vs no-rotation made no
difference to the outcome in either state.

## Also affects AliExpress MTop (2026-07-29, later the same day)

The same intermittency reached AliExpress's MTop product API, which had been
working all day and is a different endpoint family from the web search path:

```
get_aliexpress_product(1005006320253339)
-> "Could not retrieve product details. MTop API may be blocked."  (2/2, 0.3s and 4.2s)
```

It also failed inside the container image on four consecutive gate runs
(20.9s, 23.4s, 24.6s, 49.4s) while passing on the host minutes earlier. So the
gating is not confined to `/trade/search` — it moves across Alibaba-group
endpoints and comes and goes on a timescale of tens of minutes. Worth treating
as one upstream behaviour rather than three separate site bugs.

## Out of scope for fetchaller

Per the fetchaller/wafer boundary, fetchaller does no challenge solving,
impersonation, or cookie work — it calls `session.get()` and surfaces what comes
back. Its `search_alibaba` / `get_alibaba_product` tools are blocked by this
(8/8 failures); `search_aliexpress` still works because it uses the MTop API
rather than the web search URL, which is further evidence the gate is on the
search *path*.

No claim is made about IP reputation or the egress network: the same host and
network fetch alibaba.com's home and product pages successfully in the same
minute, and reached search successfully earlier the same day.
