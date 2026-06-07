# TODO: Reliably pass wellfound.com (DataDome + Cloudflare Turnstile) — handoff spec

**Owner:** wafer
**Status:** RESOLVED (2026-06-06) -wafer already handles it; no code change
**Consumer:** fetchaller-mcp wellfound.com search/job/company feature is blocked on this.

---

## RESOLUTION (2026-06-06)

Verified firsthand (not trusting this spec). **wafer already returns the real
SSR document for all four page types** with `session.get(url, browser_solver=...)`,
2/2 live each:

| Page type | Path | How |
|---|---|---|
| Jobs listing | `/jobs` | **no browser** -> 200 `__NEXT_DATA__` apolloState |
| Role search | `/role/r/{role}` | DD 403 -> browser passive passthrough -> 200 `__NEXT_DATA__` |
| Company | `/company/{slug}` | DD 403 -> browser passthrough -> 200 `__NEXT_DATA__` |
| Job detail | `/jobs/{id}` | DD 403 -> browser passthrough -> 200 `JobPosting` JSON-LD |

Why this spec's premises were wrong:

- **Detection already fires.** The block is a 403 carrying a `datadome` cookie +
  `captcha-delivery` body marker, so `_challenge.py` classifies it `datadome`
  today. The white-labeling is only at the JS-tag host (`ddm.wellfound.com/js/`);
  the captcha iframe is still `captcha-delivery`, which the solver keys on.
- **DO NOT extend detection to `window.ddjskey`/`ddoptions`/`ddm.<site>.com/tags.js`**
  as §4 suggested. Those scripts are embedded on **every** wellfound page,
  including the **successful SSR `/jobs` 200**. Detecting on them false-positives
  on real content and loops the solver forever (same class of bug as the Imperva
  `_Incapsula_Resource` marker).
- **Turnstile is not in the navigation path.** The `cf-mitigated` Turnstile flow
  only gates client-side GraphQL XHRs; fetchaller needs only the SSR document,
  which the browser passthrough returns. (A direct `/graphql` POST is a separate
  Cloudflare 403, correctly classified distinct from the DD page challenge.)

Net: no wafer change required. Documented in `docs/site-list.md`. The only thing
to keep is the existing DataDome solver + passthrough, which already works.

Original spec retained below for reference.

---

fetchaller does NOT and MUST NOT do any bot-challenge detection, solving, or
cookie handling — that is all wafer's responsibility. fetchaller only calls
`session.get(url, browser_solver=<shared solver>)` and parses the returned HTML.
This spec is for wafer.

---

## 1. What fetchaller needs to work

All four wellfound page types are **server-rendered** — the data fetchaller needs
is embedded in the **initial HTML document** (`__NEXT_DATA__` apolloState, or a
`schema.org/JobPosting` JSON-LD block). fetchaller does **not** need wafer to run
the page's client-side GraphQL XHRs; it only needs the real initial document
back.

| Page type | URL pattern | Data in the SSR document |
|---|---|---|
| Jobs listing | `https://wellfound.com/jobs` | `__NEXT_DATA__` → `apolloState.data` with `JobListing` + `Startup` |
| Role / location search | `https://wellfound.com/role/r/{role}` (remote), `/role/l/{role}/{location}`, `/location/{location}` | `__NEXT_DATA__` → `apolloState.data` with `JobListingSearchResult` + `StartupResult` + a `Results` pagination object |
| Job detail | `https://wellfound.com/jobs/{id}-{slug}` | `schema.org/JobPosting` JSON-LD (no `__NEXT_DATA__`) |
| Company | `https://wellfound.com/company/{slug}` | `__NEXT_DATA__` → `apolloState.data` with a full `Startup` object |

So the only thing wafer must defeat is whatever challenge gates the **initial
page navigation**. If the navigation returns the real document, fetchaller is
done.

---

## 2. The block — a stacked DataDome + Cloudflare Turnstile setup

The served HTML head shows two layered protections:

**(a) DataDome, deployed first-party (CNAME'd onto wellfound's own subdomain):**
```html
<script>
  window.ddjskey = "BA3EB296E8BE96A496929870E20CD4";
  window.ddoptions = {"ajaxListenerPath":"wellfound.com","overrideAbortFetch":true,
                      "allowHtmlContentTypeOnCaptcha":true,"endpoint":"https://ddm.wellfound.com/js/"};
</script>
<script src="https://ddm.wellfound.com/tags.js" async></script>
```
Note this is **not** the standard `js.datadome.co` / `geo.captcha-delivery.com`
hosts — DataDome is white-labeled behind `ddm.wellfound.com`.

**(b) Cloudflare Turnstile, triggered on XHR responses (not a full-page
interstitial):** the page overrides `window.fetch`; when a GraphQL/XHR response
carries the header `cf-mitigated: challenge`, it shows an in-page Turnstile
widget ("One more step before you proceed…", `#turnstile_widget`,
`challenges.cloudflare.com`), solves it, then replays the request:
```js
turnstileLoad = function () {
  const originalFetch = window.fetch;
  ...
  window.fetch = async function (...args) {
    let response = await originalFetch(...args);
    if (!challengeInProgress && response.headers.get('cf-mitigated') === 'challenge') {
      // show Turnstile widget, solve, retry
    }
  }
}
```

The failure mode: instead of the SSR document, wafer gets a DataDome block /
interstitial (or an empty shell), so none of the `__NEXT_DATA__` / JSON-LD data
is present and fetchaller has nothing to parse.

---

## 3. Evidence

- The data fetchaller needs is confirmed **SSR** — captured documents for all four
  page types contained the real embedded data (`__NEXT_DATA__` apolloState with
  `JobListing`/`JobListingSearchResult`/`Startup`/`StartupResult`, or JSON-LD
  `JobPosting`). So when the navigation gate passes, the content is right there in
  the initial document — no XHR execution required.
- wellfound is currently **not returning that document reliably through wafer**
  (block / challenge response instead). The navigation-level DataDome+Turnstile
  pass is not reliable.
- This is about wafer's request + solve handling for this protection stack, not
  the network — do not attribute it to the IP.

Reproduce (capture both the success and the failing response):
```python
import asyncio
from wafer.browser import BrowserSolver
import wafer
from datetime import timedelta

URLS = [
    "https://wellfound.com/jobs",
    "https://wellfound.com/role/r/product-manager",
    "https://wellfound.com/jobs/4011096-ceo-loopp-com",   # job detail (JSON-LD)
    "https://wellfound.com/company/fayco",
]
async def main():
    s = wafer.AsyncSession(browser_solver=BrowserSolver(), timeout=timedelta(seconds=90))
    for u in URLS:
        r = await s.get(u)
        html = r.text
        ok = ('__NEXT_DATA__' in html and 'apolloState' in html) or 'JobPosting' in html
        blocked = 'ddjskey' in html and not ok   # DataDome shell w/o SSR data
        print(u, r.status_code, 'OK' if ok else ('BLOCKED' if blocked else '???'), len(html))
        await asyncio.sleep(8)
asyncio.run(main())
```
Success = the SSR data markers are present. Failure = a DataDome/Turnstile page
(or a shell carrying `ddjskey` but no `__NEXT_DATA__`/`JobPosting`).

---

## 4. Current wafer behaviour & likely gaps

wafer already ships solvers for both systems:
- `wafer/browser/_datadome.py` — but it keys on the standard `captcha-delivery`
  iframe URL. wellfound serves DataDome from the **first-party** host
  `ddm.wellfound.com`, so detection/solve may not fire. Detection should also key
  on `window.ddjskey` / `window.ddoptions` / `ddm.<site>.com/tags.js` and the
  DataDome cookie — not just `captcha-delivery`.
- `wafer/browser/_cloudflare.py` — targets full-page Turnstile interstitials.
  wellfound's Turnstile is **XHR-triggered** via the `cf-mitigated: challenge`
  response header + an in-page widget, which is a different shape. (Only relevant
  if the **initial navigation** is challenged — see scope note below.)

Detection entry points to extend: `wafer/_challenge.py` (add the first-party
DataDome signatures above; recognize `cf-mitigated: challenge`), dispatch in
`wafer/browser/_solver.py`.

The dev should also capture wafer's exact outbound navigation request
(TLS/JA3-JA4, HTTP/2 settings + header order/casing, cookies) and diff it against
a real Chrome navigation to wellfound to find what triggers the challenge — the
cheapest fix is to not get challenged on the navigation at all.

---

## 5. Success criteria (definition of done)

1. `wafer.AsyncSession(browser_solver=...).get(url)` returns the **real SSR
   document reliably** (target ≥ 19/20 over repeated fresh-session runs) for all
   four page types in §1: the response contains `__NEXT_DATA__` with
   `apolloState.data` entries of type `JobListing` / `JobListingSearchResult` /
   `Startup` / `StartupResult` (listing/search/company), or a `schema.org/JobPosting`
   JSON-LD block (job detail) — **not** a DataDome interstitial or Turnstile
   "One more step" page or a shell missing the SSR data.
2. **Scope:** fetchaller needs only the initial SSR document; wafer does **not**
   need to execute the page's GraphQL XHRs. The `cf-mitigated`/Turnstile XHR flow
   only matters if the **initial navigation** is itself challenged.
3. DataDome detection + solve covers the **first-party `ddm.wellfound.com`**
   deployment; the solve sets the DataDome cookie and the retried navigation
   returns the document.
4. **No regression** on standard DataDome / Cloudflare Turnstile sites.
5. **Zero fetchaller changes.** fetchaller calls `session.get(url, browser_solver=...)`
   and parses the returned HTML — no cookie seeding, no retries-as-workaround, no
   wellfound-specific logic on the fetchaller side.

### How fetchaller will verify once wafer ships it
Fetch each of the four URL types through `fetch_url(raw=True)` repeatedly and
confirm the SSR data markers are present every time, with no DataDome/Turnstile
challenge body leaking through.
