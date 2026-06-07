# TODO: Reliably pass api2.realtor.ca (Imperva) — handoff spec

**Owner:** wafer
**Status:** RESOLVED (2026-06-06) -no browser required
**Consumer:** fetchaller-mcp realtor.ca search/listing feature is blocked on this.

---

## RESOLUTION (2026-06-06)

The TODO's hypothesis (missing interactive-checkbox solve) was wrong. Root
cause, established by first-hand wire testing on the same IP (not trusting the
table below):

- **api2 fingerprints the TLS stack.** Every wreq profile -Chrome and Safari,
  HTTP/1.1 and HTTP/2, even carrying valid `visid_incap`/`nlbi`/`incap_ses`
  cookies that curl just earned a 200 with -gets the reese84 challenge. wreq is
  BoringSSL; rotating fingerprints can't escape it. So cookie replay and
  fingerprint rotation are both dead ends here.
- **curl / Python-urllib (system OpenSSL) get a free pass** -*if* they omit
  `Sec-Fetch-*`. Isolated it: `sec-ch-ua` present + no `Sec-Fetch` → 200;
  `Sec-Fetch` present → 403, regardless of TLS. Imperva holds anything that
  looks like a browser fetch (Sec-Fetch + browser TLS) to the JS standard and
  waves through plain API clients.
- The Sec-Fetch *contradiction* wreq emits (Emulation injects
  `sec-fetch-site:none` + `sec-fetch-mode:navigate` while the caller adds
  `Origin`) is what was escalating to the **interactive checkbox**; it's a
  symptom, not the cause.

**Fix:** a native-TLS fallback transport (`wafer/_native_tls.py`, stdlib urllib
over system OpenSSL) that wafer auto-invokes on Imperva detection and pins
per-host. It strips `Sec-Fetch-*`/`Sec-Ch-Ua`, keeps `Origin`/`Referer`, and
carries any GET/POST body. No browser, no fetchaller changes. Wired into both
`_async.py` and `_sync.py` (trigger + sticky routing with rate-aware backoff).

**Verified no-browser, full flow:** SubAreaSearch (geocode) → LocationDescription
(polygons) → PropertySearch_Post (map view) → list view (RecordsPerPage=50) →
pagination pages 2-3 -all 200 + JSON, real listings/polygons/paging returned.
Caveat: rapid-firing the endpoint trips a *rate-based* reese84 page even on
OpenSSL (recovers after a cooldown; the sticky path backs off and retries).

Tests: `tests/test_native_tls.py`. See memory `imperva_native_tls_bypass.md`.

Original spec retained below for reference.

---

fetchaller does NOT and MUST NOT do any of this — all bot-challenge detection,
solving, and cookie handling is wafer's responsibility. fetchaller only calls
`session.get/post(..., browser_solver=<shared solver>)`. This spec is for wafer.

---

## 1. What fetchaller needs to work

The realtor.ca home-search feature depends on three Imperva-protected XHR
endpoints on `api2.realtor.ca`. The public `www.realtor.ca/map` page is an empty
shell; **all** search results come from these calls, so there is no HTML
fallback — wafer MUST be able to hit api2 reliably.

The browser issues these as CORS XHRs from origin `https://www.realtor.ca` with
`Origin` + `Referer` set to the site.

1. **Geocode** (GET):
   ```
   https://api2.realtor.ca/Location.svc/SubAreaSearch?Area=Ottawa&ApplicationId=1&CultureId=1&Version=7.0&CurrentPage=1
   ```
   → JSON with `SubArea[0].Viewport` (NE/SW lat-long bbox) + `GEOId`.

2. **Search** (POST, `application/x-www-form-urlencoded`):
   ```
   https://api2.realtor.ca/Listing.svc/PropertySearch_Post
   ```
   Working body (bbox comes from the geocode viewport):
   ```
   LatitudeMax=45.5375801&LongitudeMax=-75.2465979&LatitudeMin=44.962733&LongitudeMin=-76.3539159
   &Sort=6-D&PropertyTypeGroupID=1&TransactionTypeId=2&PropertySearchTypeId=0
   &GeoIds=g30_f241etq5&Currency=CAD&IncludeHiddenListings=false
   &RecordsPerPage=12&ApplicationId=1&CultureId=1&Version=7.0&CurrentPage=1
   ```
   → JSON `{ Paging:{TotalRecords,...}, Results:[...] }`.

3. **Location detail** (GET, used for polygon scoping):
   ```
   https://api2.realtor.ca/Location.svc/LocationDescription?GeoId=g30_dpz89rm7&CultureId=1&IncludePolygons=true&ApplicationId=1&Version=7.0&CurrentPage=1
   ```

Required request headers on all three: `Origin: https://www.realtor.ca`,
`Referer: https://www.realtor.ca/`.

---

## 2. The block

api2 is behind Imperva/Incapsula (`x-cdn: Imperva`, `x-iinfo` header; cookies
`visid_incap_2271082`, `nlbi_2271082`, `incap_ses_1226_2271082`; Imperva site id
`2271082`, Incapsula instance `1226`).

When wafer's request is flagged, Imperva serves the **interactive "I'm not a
robot" checkbox interstitial** ("Access Denied — Error 15 … Just click the I'm
not a robot checkbox to pass the security check … Powered by Imperva", Incident
ID prefixed `1226…`). This is an interactive challenge, not the passive JS
(`reese84`) variant.

---

## 3. Evidence (this is NOT an IP/network problem)

All three observations are from the **same machine / same egress IP**:

| Client | Request | Result |
|---|---|---|
| `curl` | GET `SubAreaSearch` (browser UA + Origin/Referer, no cookies) | **HTTP 200** + JSON, fresh Imperva `Set-Cookie` |
| `wafer.AsyncSession` (no `browser_solver`) | same GET | **`ChallengeDetected: imperva` (HTTP 403)** |
| `wafer.AsyncSession` (with `browser_solver`) | geocode + `PropertySearch_Post` | **Works when Imperva serves the passive JS challenge** (returned 300 filtered results); **fails with the Error 15 checkbox interstitial intermittently** |

Because curl succeeds and wafer fails on the **identical IP**, the discriminator
is in **wafer's outbound request** (TLS/HTTP2/header fingerprint and/or cookie
handling) and in the **missing interactive-checkbox solve** — not the network.
Do not attribute this to the IP.

### Repro

```bash
# Baseline — succeeds (200 + Set-Cookie), proves the IP is fine:
curl -s -i "https://api2.realtor.ca/Location.svc/SubAreaSearch?Area=Ottawa&ApplicationId=1&CultureId=1&Version=7.0&CurrentPage=1" \
  -H "Origin: https://www.realtor.ca" -H "Referer: https://www.realtor.ca/" \
  -A "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36"
```

```python
# wafer raw — reproduces the 403 (no browser_solver):
import asyncio, wafer
from datetime import timedelta
async def main():
    s = wafer.AsyncSession(timeout=timedelta(seconds=30))
    r = await s.get("https://api2.realtor.ca/Location.svc/SubAreaSearch",
                    params={"Area":"Ottawa","ApplicationId":"1","CultureId":"1","Version":"7.0","CurrentPage":"1"},
                    headers={"Origin":"https://www.realtor.ca","Referer":"https://www.realtor.ca/"})
    print(r.status_code, len(r.content))
asyncio.run(main())
```

```python
# wafer + browser_solver — succeeds on passive challenge, hits Error 15 checkbox intermittently:
from wafer.browser import BrowserSolver
s = wafer.AsyncSession(browser_solver=BrowserSolver(), timeout=timedelta(seconds=60))
# ...same GET, then POST PropertySearch_Post with the body in §1...
```

---

## 4. Current wafer behaviour (what exists vs the gap)

**Detection works.** api2's block is correctly classified as `IMPERVA`:
- `wafer/_challenge.py:103-112` — `reese84`/`___utmvc` cookie + 403/429; `x-cdn` incapsula/imperva
- `wafer/_challenge.py:262-267` — body markers
- `wafer/_challenge.py:305-328` — the HTTP-200 interstitial (added in 0.2.2)

**Solve is incomplete.** `wafer/browser/_imperva.py:26 wait_for_imperva()` only
**polls for a JS-set solve cookie** (`reese84` / `___utmvc` / `incap_ses_*`) to
appear or change, then replays. It never interacts with the page — there is **no
checkbox click**. Dispatch: `wafer/browser/_solver.py:1503` routes `imperva` →
`wait_for_imperva` only.

So when Imperva serves the interactive "I'm not a robot" interstitial,
`wait_for_imperva` has nothing to click, times out, and the block persists.

Note: the 0.2.2 change ("detect Imperva 200 interstitial; bound browser-solve
timeout") improved **detection** but did not add interactive checkbox
**solving**.

### Reference implementations already in wafer (mirror these)
Interactive checkbox/iframe solving the Imperva path should follow:
- `wafer/browser/_cloudflare.py` — Turnstile: locate challenge iframe, human-like
  body click, `patch_frame_screenxy`, retry-click loop, early bail-out.
- `wafer/browser/_datadome.py` — `captcha-delivery` iframe, mouse-replay click via
  the `mousse` movement engine, hard-block detection, post-click cookie wait.
- `wafer/browser/_hcaptcha.py`, `wafer/browser/_recaptcha.py` — checkbox click +
  solve-cookie wait patterns.

The dev should also capture wafer's exact outbound request (TLS/JA3-JA4, HTTP/2
settings + header order, header set/casing, and any replayed cached Imperva
cookies) and diff it against a real Chrome XHR to api2 to find what triggers the
escalation in the first place — the cheapest fix is to not get escalated to the
checkbox at all.

---

## 5. Success criteria (definition of done)

1. `wafer.AsyncSession(browser_solver=...)` GET/POST to all three api2 endpoints
   in §1 returns **HTTP 200 + valid JSON reliably** (target ≥ 19/20 over repeated
   fresh-session runs), **including** when Imperva serves the Error 15 checkbox
   interstitial.
2. When Imperva serves the **interactive "I'm not a robot" checkbox**, wafer's
   Imperva solver **detects it, performs the human-like click, waits for the
   post-solve cookie** (`incap_ses_*` / `reese84`), and **replays the original
   request transparently** (caller just gets the JSON back).
3. Solved Imperva cookies are **persisted/scoped** so subsequent api2 calls in the
   same session reuse them (no re-solve per request); stale/expired cookies are
   never replayed in a way that itself causes a 403 — a fresh request must be able
   to earn fresh cookies (curl with no cookies gets 200).
4. The passive `reese84`/`incap_ses` path keeps working — **no regression** on
   sites that currently pass via `wait_for_imperva`.
5. **Zero fetchaller changes required.** fetchaller continues to call
   `session.get/post(..., browser_solver=...)` only — no cookie seeding, no
   retries-as-workaround, no api2-specific logic on the fetchaller side.

### How fetchaller will verify once wafer ships it
Run the geocode → `PropertySearch_Post` flow (§1) through `fetch_url()` /
`search_realtor` repeatedly and confirm 200 + results every time, with no
`ChallengeDetected: imperva` and no Error 15 body leaking through.
