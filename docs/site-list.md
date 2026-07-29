# Site List -WAF Benchmark Targets

> **Every site in this list must be manually verified before relying on its WAF classification.**
> WAFs change vendors, update configurations, and add/remove protections frequently.
> Never assume a site's challenge type -confirm by inspecting response headers, cookies,
> and body content against a live fetch. Mark unverified sites accordingly.

## Maintenance Rules

**Keep this list continuously up to date.** WAF challenges are intermittent -a site that passes today may challenge tomorrow. Update whenever:

- A site escalates to a browser challenge or interactive CAPTCHA during testing
- A previously-passing site starts returning 403s or challenge pages
- A new WAF vendor, challenge type, or unique behavior is encountered
- A site's tier changes (e.g., was Tier 2 TLS-only, now requires browser solve)
- Live testing produces new status data (pass/fail/browser-solve)

When updating, change the **Status** column and add a date + note. Don't assume a site's current behavior is permanent.

**Status values:**
- `pass` -confirmed working via TLS only (wreq Emulation)
- `browser-solve` -needs browser solver, confirmed working
- `browser-passthrough` -browser returns the validated response body directly
- `no-solver` -challenge has no dedicated wafer solver
- `no-drag` -challenge needs a dedicated drag flow wafer does not implement
- `untested` -not yet tested
- `unverified` -WAF claim not confirmed in latest smoke test (may trigger on deeper pages)
- `blocked` -wafer did not reproduce the successful real-browser behavior; record the observed code path without attributing the cause externally
- `render` -no WAF; the server ships a client-rendered shell and the content only exists after `session.render()`

---

## Tier 0: No Protection (baseline)

| URL | Challenge Type | Status | Notes |
|---|---|---|---|
| `httpbin.org/get` | None | pass | JSON with correct headers |
| `httpbin.org/headers` | None | pass | Echoes all headers |
| `httpbin.org/anything` | None | pass | Full request echo |
| `example.com` | None | pass | Static HTML |

## Tier 0b: Client-Rendered Shells (no WAF, needs render)

The server answers 200 with a shell; the content is written by JavaScript.
`resp.needs_render` is True on the plain fetch and `session.render(url)` returns
the finished document. These are render regression targets, not WAF targets.

| URL | Shell -> Rendered (visible text) | Status | Notes |
|---|---|---|---|
| `www.greypointindustries.com` | 20 -> ~2,900 chars | render | Vite SPA, `<div id="root">`; whole page is client-written (verified 2026-07-29) |
| `strategicmissions.ca/careers` | 539 -> ~1,900 chars | render | Open Roles fetched client-side from BambooHR (verified 2026-07-29) |
| `www.lodge.tech` | 846 -> ~400 chars | render | Framer. Raw HTML carries duplicated breakpoint variants; the render de-duplicates them and adds the nav + footer the shell omits. Lower char count is correct -the site is a one-pager (verified 2026-07-29) |
| `csmc.bamboohr.com/careers` | 8 chars of visible text | render | Job data is embedded JSON; 200 over TLS, render only needed for visible text (verified 2026-07-29) |

## Terminal Blocks (nothing to solve)

Denials, not challenges. wafer classifies these as `cloudflare_block` and raises
`RequestBlocked` on the first response with zero rotations. They are regression
targets for that classification, not solve targets.

| URL | Challenge Type | Status | Notes |
|---|---|---|---|
| `airmatrix.ca` | `cloudflare_block` | blocked | Parked/abandoned zone (Cloudflare NS, no live origin); the company's real site is `airmatrix.ai`, which fetches 200 over plain TLS. Error 1020 to every client from every network -verified against wafer, a real headed Chrome, curl, and check-host nodes in 4 countries (2026-07-29). Body captured at `tests/fixtures/cloudflare_waf_block_1020.html` |

## Tier 1: UA Check Only

Should pass with any Chrome Emulation profile.

| URL | Challenge Type | Status | Notes |
|---|---|---|---|
| `ticketmaster.com` | Akamai (lenient) | pass | Basic UA check |
| `nytimes.com` | Minimal | pass | Basic UA check, Datadog RUM only |

## Tier 2: TLS Fingerprint Required

Passes with wreq Chrome Emulation (JA3/JA4 + H2 fingerprint match).

### Cloudflare

| URL | Challenge Type | Status | Notes |
|---|---|---|---|
| `vinted.com` | Cloudflare + JA3 | pass | 200 with Chrome TLS; CF at network level |
| `car.gr` | Cloudflare | pass | 2026-02-21: 200 176KB via TLS. Greek automotive marketplace |
| `draftkings.com` | Cloudflare | pass | 2026-02-21: 200 200KB via TLS. Sports betting |
| `nbcsports.com` | Cloudflare | pass | 2026-02-21: 200 1.1MB via TLS. NBC media/sports |

### Akamai

| URL | Challenge Type | Status | Notes |
|---|---|---|---|
| `aircanada.com` | Akamai (_abck + bm_sz) | pass | 301 -> Akamai challenge page with sensor scripts |
| `crateandbarrel.com` | Akamai (_abck) | pass | 2026-02-21: 200 689KB via TLS. Sensor script + akam-sw.js service worker confirmed |
| `nike.com` | Akamai (_abck + bm_sz) | pass | 2026-02-21: 200 691KB via TLS |
| `www.ebay.com` | Akamai (_abck) | pass | 2026-02-21: 200 806KB via TLS. Bare `ebay.com` redirects to `www.` |
| `www.delta.com` | Akamai | pass | 2026-02-21: 200 16KB via TLS. Airline-grade Akamai; small homepage. Bare `delta.com` refuses connections -must use `www.` |
| `costco.com` | Akamai | pass | 2026-02-21: 200 3.4MB via TLS. Major US warehouse retail |
| `kroger.com` | Akamai | pass | 2026-02-21: 200 513KB via TLS. Major US grocery |
| `samsclub.com` | Akamai | pass | 2026-02-21: 200 495KB via TLS. Walmart subsidiary |

### PerimeterX/HUMAN

| URL | Challenge Type | Status | Notes |
|---|---|---|---|
| `stockx.com` | PerimeterX | pass | PX appId `PX16uD0kOF` confirmed |
| `digikey.com` | PX + Cloudflare | pass | PX appId `lO2Z493J` confirmed; CF at network level |
| `weedmaps.com` | PerimeterX | pass | 2026-02-21: 200 466KB via TLS. Cannabis marketplace |
| `citygear.com` | PerimeterX | pass | 2026-02-21: 200 359KB via TLS. Redirects to dtlr.com |
| `asda.com` | PerimeterX | pass | 2026-02-21: 200 369KB via TLS. UK grocery retailer |

### AWS WAF

| URL | Challenge Type | Status | Notes |
|---|---|---|---|
| `traveloka.com` | AWS WAF (aws-waf-token) | pass | 2026-02-21: 200 990KB via TLS. No WAF challenge on homepage |
| `similarweb.com` | AWS WAF | pass | 2026-02-21: 200 832KB via TLS. `awswaf.com` SDK + `challenge.js` confirmed |

### Imperva/Incapsula

| URL | Challenge Type | Status | Notes |
|---|---|---|---|
| `whoscored.com` | Imperva (unverified) | pass | 2026-02-21: 200 553KB via TLS. Sports stats; no Imperva challenge on homepage |
| `psacard.com` | Imperva (unverified) | pass | 2026-02-21: 200 126KB via TLS. Redirects to /en-CA. Collectibles grading |

### DataDome

| URL | Challenge Type | Status | Notes |
|---|---|---|---|
| `marketwatch.com` | DataDome (unverified) | pass | 2026-02-21: 200 638KB via TLS. Financial news; no DD challenge on homepage |

### Kasada

| URL | Challenge Type | Status | Notes |
|---|---|---|---|
| `godaddy.com` | Kasada (unverified) | pass | 2026-02-21: 200 339KB via TLS. Redirects to /en-ca. Largest Kasada deployment |
| `arcteryx.com` | Kasada (unverified) | pass | 2026-02-21: 200 234KB via TLS. Redirects to /ca/en. Kasada press-and-hold reported |

### F5 Shape

| URL | Challenge Type | Status | Notes |
|---|---|---|---|
| `chase.com` | Shape (unverified) | pass | 2026-02-21: 200 403KB via TLS. Banking; no Shape interstitial on homepage |

### Unknown / Other

| URL | Challenge Type | Status | Notes |
|---|---|---|---|
| `footdistrict.com` | Unknown | pass | 2026-02-21: 200 1.6MB via TLS. European sneaker store; WAF not identified |

## Tier 3: Browser Challenge

Requires the browser solver. Depending on the WAF, wafer either replays earned
cookies through the TLS client or returns a validated browser response.

### Cloudflare

| URL | Challenge Type | Status | Notes |
|---|---|---|---|
| `scrapingcourse.com/cloudflare-challenge` | CF + Turnstile | browser-solve | 2026-02-21: Browser-solve verified. 403→browser→cf_clearance→200 4KB. **2026-07-27 re-verified on system Chrome 150.0.7871.182** (newer than `DEFAULT_EMULATION`): challenge→browser passthrough (7 cookies)→200 4,264B in 6.2s, `cf_clearance` present, and the immediate replay returned 200 in **0.3s with no challenge**. Confirms a UA-bound CF clearance minted by Chrome 150 replays over wreq under the pinned Chrome 150 UA + Chrome 149 TLS. |
| `scrapingcourse.com/antibot-challenge` | CF + Turnstile | browser-solve | 2026-02-21: Browser-solve verified. 403→browser→cf_clearance→200 4KB |
| `nowsecure.nl` | Cloudflare Turnstile | pass | 2026-02-21: 200 180KB via TLS -no challenge triggered |
| `hltv.org` | Cloudflare | pass | 2026-02-21: 200 421KB via TLS. CF CDN confirmed; challenge not triggered |
| `crunchbase.com` | Cloudflare | pass | 2026-02-21: 200 799KB via TLS. No CF challenge on homepage; login wall on company data |
| `capterra.com/categories` | Cloudflare | pass | 2026-02-21: 200 616KB via TLS |
| `fiverr.com` | Cloudflare | pass | 2026-02-21: 200 1.9MB via TLS |
| `miata.net` | Cloudflare | browser-solve | 2026-02-21: Browser-solve verified. 403→browser→cf_clearance→200 26KB |
| `researchgate.net/publication/352299571_Additives_in_pet_food_are_they_safe` | CF managed + Turnstile | browser-solve | 2026-03-06: Browser-solve verified. 403→browser→passthrough→200 710KB. Custom CF challenge page (ResearchGate branding). Alternates between managed (auto-solve) and interactive Turnstile. Detected `--disable-site-isolation-trials` flag - required removing it for Turnstile to resolve. |
| `glassdoor.com` | Cloudflare | pass | 2026-02-21: 200 648KB via TLS |
| `kick.com` | Cloudflare | browser-solve | 2026-02-21: Browser-solve verified. 403→browser→cf_clearance→200 502KB. **Reclassified from Kasada to Cloudflare** |
| `fbref.com` | Cloudflare | browser-solve | 2026-02-21: Browser-solve verified. 403→browser→cf_clearance→200 554KB. Sports reference |
| `manta.com` | Cloudflare | browser-passthrough | 2026-07-28: reverified live. Initial wreq response was a Cloudflare challenge; headed Chrome reached the real page and wafer returned the post-solve HTML passthrough (200, 110,183 bytes, 20 cookies, zero rotations). This supersedes the 2026-02-21 `blocked` classification. |
| `apollomapping.com` | Cloudflare | browser-passthrough | 2026-07-28: wreq receives a CF 403 while headed Chrome receives the real page with no challenge iframe. Verified the challenge-absent main-document passthrough returns the actual 200 HTML response (218,487 bytes on final recheck), with zero fingerprint rotations, no fingerprint pin, the original wreq client preserved, and stale wire encoding/length headers removed. |

### Cloudflare Turnstile

| URL | Challenge Type | Status | Notes |
|---|---|---|---|
| `scrapingcourse.com/login/cf-turnstile` | Turnstile + login | pass | 2026-02-21: 200 9KB via TLS -login form renders without challenge |
| `2captcha.com/demo/cloudflare-turnstile` | Turnstile widget | pass | 2026-02-21: 200 243KB via TLS -demo page renders without challenge |

### DataDome

| URL | Challenge Type | Status | Notes |
|---|---|---|---|
| `g2.com` | DataDome | pass | 2026-02-21: 200 420KB via TLS -no DD challenge on homepage. Previously required browser-solve. |
| `airbnb.com` | DataDome | pass | 2026-02-21: 200 583KB via TLS -no DD challenge on homepage |
| `neimanmarcus.com` | DataDome | browser-solve | 2026-02-21: Browser-solve verified. 403→browser→datadome cookie→200 760KB. 2026-02-22: passed TLS-only (intermittent) |
| `idealista.com` | DataDome | browser-solve | 2026-02-21: Browser-solve verified. 403→browser→datadome cookie→200 89KB |
| `ra.co` | DataDome | pass | 2026-02-21: 200 340KB via TLS (3.0s slow) |
| `klwines.com` | DataDome | pass | 2026-02-21: 200 292KB via TLS |
| `leboncoin.fr` | DataDome | pass | 2026-02-21: 200 357KB via TLS -no DD challenge on homepage |
| `allegro.pl` | DataDome | browser-solve | 2026-02-21: Browser-solve verified. 403→browser→datadome cookie→200 1.3MB |
| `deezer.com` | DataDome | pass | 2026-02-21: 200 188KB via TLS |
| `tripadvisor.com` | DataDome | browser-solve | 2026-02-21: Browser-solve verified. 403→browser→datadome cookie→200 379KB. Major travel site. 2026-02-22: passed TLS-only (intermittent) |
| `wellfound.com` (4 SSR page types) | DataDome (white-labeled `ddm.wellfound.com`) | pass + browser-solve | 2026-06-06: All 4 SSR types verified 2/2 live, each returns the real initial document. `/jobs` passes **no-browser** (200, `__NEXT_DATA__` apolloState). `/role/r/{role}`, `/company/{slug}`, `/jobs/{id}` return DD **403** fresh-session -> existing browser DataDome solver passes them via **passive passthrough** (white-labeled tag.js at `ddm.wellfound.com/js/`, captcha iframe still `captcha-delivery`): 200 with `__NEXT_DATA__`/`JobPosting` JSON-LD. **No code change needed** -current detection (datadome cookie + `captcha-delivery` on 403) already fires. **DO NOT detect on `window.ddjskey`/`ddoptions`** as the stale TODO suggested: those scripts are embedded on EVERY wellfound page including the successful SSR `/jobs` 200, so it would false-positive into an infinite solve loop. GraphQL POST to `wellfound.com/graphql` is a separate **Cloudflare** 403 (`cf-mitigated: challenge`), but fetchaller needs only the SSR document, not the XHRs. **2026-07-27 re-verified on system Chrome 150.0.7871.182:** all three page types return 200 with `__NEXT_DATA__` -- `/role/r/*` 513KB via browser passthrough (11 cookies) in 6.5s, then `/company/*` and `/jobs` replay in 0.1s each. An earlier run in this session reported `DataDome hard block detected (IP/device flagged)` and was written up as a burned egress. **That was wrong.** A plain headed browser loaded the page from the same machine with no captcha iframe at all, and a fresh `BrowserSolver` passed it in 6.4s. The real causes were both wafer-side: the `page.goto()` budget bug that consumed the whole solve deadline (fixed), and reusing a single solver across many different sites in one batch. Never treat wafer's own hard-block log line as evidence that the network is at fault. **Headed only:** headless fails here (`ChallengeDetected`) because DataDome's tag.js fingerprints at document start and the headless fingerprint patches only land after it; other WAFs that fingerprint later do pass headless. |

### Akamai

| URL | Challenge Type | Status | Notes |
|---|---|---|---|
| `lowes.com` | Akamai (full sensor) | pass | 2026-02-21: 200 449KB via TLS |
| `expedia.com` | Akamai | pass | 2026-02-21: 200 466KB via TLS |
| `marriott.com` | Akamai | pass | 2026-02-21: 200 1.0MB via TLS |
| `southwest.com` | Akamai | pass | 2026-02-21: 200 7KB via TLS (small homepage) |
| `united.com` | Akamai | pass | 2026-02-21: 200 70KB via TLS |
| `adidas.com` | Akamai | pass | 2026-02-21: 200 893KB via TLS |
| `mouser.com` | DataDome | browser-solve | 2026-02-21: Browser-solve verified. 403→browser→datadome cookie→200 219KB. **Reclassified from Akamai to DataDome** |
| `bestbuy.com` | Akamai | pass | 2026-02-21: 200 7KB via TLS (small homepage). `bazadebezolkohpepadr` + `/akam/` paths confirmed |
| `hyatt.com` | Kasada + Akamai | browser-solve | 2026-02-21: Browser-solve verified. 429→browser→kasada cookies→200 42KB. **Primary WAF is Kasada**; Akamai CDN layer only |
| `starbucks.com` | Akamai | pass | 2026-02-21: 200 102KB via TLS |

### Imperva/Incapsula

| URL | Challenge Type | Status | Notes |
|---|---|---|---|
| `realtor.ca/on/st-catharines-niagara/real-estate` | Imperva (reese84 interstitial) | browser-solve | 2026-06-06: After a few rapid requests, serves the "Pardon Our Interruption" interstitial as **HTTP 200** (~6.4KB), not a 403. Now detected via interstitial-only JS markers (`reeseSkipExpirationCheck`, `interstitial-inprogress`) since the `_Incapsula_Resource` sensor also appears on real pages, so the marker alone would false-positive after a solve. Browser-solve verified: 200 interstitial→browser→reese84→200 362KB real page (8.3s). **2026-07-27 re-verified on system Chrome 150.0.7871.182**: a single cold request passes on TLS alone (200/286KB, 3.0s, no interstitial). After a deliberate 3-6 request burst the host escalates and interstitials every request; it then still resolves to 200/346KB of real page, but via `Imperva bypassed via native-TLS (host pinned)` and taking **144.8s**. Under a 75s budget the *browser* solve timed out twice (53.4s, 69.9s) -- in both cases the solve actually completed (`cookie_count=4`) just after the caller gave up, so the path works but does not fit a short budget once the host is escalated. Re-measure from an unburst egress before treating the 8.3s figure as current. |
| `api2.realtor.ca/Location.svc/*`, `api2.realtor.ca/Listing.svc/PropertySearch_Post` | Imperva (reese84, TLS-fingerprinting) | native-TLS + browser (heavy) | 2026-06-07: This host fingerprints the **TLS stack**. Every wreq profile (Chrome/Safari/OkHttp, H1 or H2, with or without valid `visid_incap`/`nlbi`/`incap_ses` cookies) gets the reese84 challenge; a generic OpenSSL client **without** `Sec-Fetch-*` gets 200 + JSON. **Light usage -no browser:** wafer auto-falls-back to a stdlib `http.client`/OpenSSL transport (curl-byte-identical: Host first, no Accept-Encoding/Connection) on Imperva detection, pinned per-host. Full search flow verified no-browser: SubAreaSearch→LocationDescription(polygons)→PropertySearch_Post→pagination, **12/12** 200. **Heavy usage -browser:** rapid-fire revokes the free pass and demands the reese84 token even from OpenSSL; with a `browser_solver` wafer solves reese84 **once** and wreq carries the token through (verified **18/18** under a burst; browser-earned reese84 replays cross-TLS on OpenSSL -> 200). See `docs/ref-imperva.md`. |
| `amadeus.com` | Imperva (reese84) | pass | 2026-02-21: 200 183KB via TLS -no challenge on homepage. Previously required browser-solve |
| `anz.com.au` | Imperva (reese84) | pass | 2026-02-21: 200 323KB via TLS |
| `www.hkbea.com/html/en/index.html` | Imperva (incap_ses) | pass | 2026-02-22: 200 162KB via TLS. Bare `hkbea.com` DNS NXDomain -only `www.hkbea.com` resolves. |
| `appdev.pwc.com` | Imperva (reese84 interstitial) | browser-solve | 2026-06-07: now serves the Incapsula JS interstitial (HTTP 200, ~3.3KB body with `_Incapsula_Resource` + visid_incap/nlbi/incap_ses cookies, `x-cdn: Imperva`); curl gets the same challenge page, not real content. Correctly detected `imperva` by the 0.2.2 200-interstitial logic. OpenSSL native fallback does NOT bypass it (curl is also challenged), so it falls through to browser-solve. Was a TLS pass in Feb before that site change / before interstitial detection existed. |

### AWS WAF

| URL | Challenge Type | Status | Notes |
|---|---|---|---|
| `amazon.com` | AWS WAF JS challenge | browser-solve | 2026-02-21: Browser-solve verified. 202→browser→aws-waf-token→200 790KB. 2026-02-22: passed TLS-only (intermittent) |
| `booking.com` | AWS WAF | browser-solve | 2026-02-21: Browser-solve verified. 202→browser→200 487KB. 2026-07-27 on Chrome 150: 200/1.47MB via TLS in 5.1s. A deliberate 5-request search burst also stayed clean (all 200, 1.5MB each) -- **AWS WAF never challenged**, so the solver is unexercised, not broken. |
| `shutterstock.com` | DataDome | browser-solve | 2026-02-21: Browser-solve verified. 403→browser→datadome cookie→200 978KB. **Reclassified from AWS WAF to DataDome** |
| `stubhub.com` | AWS WAF | pass | 2026-02-21: 200 182KB via TLS |

### Kasada

Kasada solver: browser solve extracts CT token from ips.js/p.js response, cookies provide session auth. CD (proof-of-work) requires ST from /tl endpoint -not all deployments provide it. Sites with dual Akamai+Kasada (e.g. Chewy) use Kasada passthrough (browser captures page content after solve) because Akamai _abck cookies are TLS-bound and can't be replayed.

| URL | Challenge Type | Status | Notes |
|---|---|---|---|
| `chewy.com` | Kasada + Akamai | browser-solve | 2026-03-02: Browser-solve verified. 429→browser→kasada passthrough→200 2.1MB. Dual-WAF: Akamai behavioral on outer layer, Kasada underneath. Full CT+CD+ST flow (ST returned from /tl). Cookie replay fails (_abck TLS-bound), uses Kasada passthrough. |
| `chewy.com/s?query=dog+food` | Kasada + Akamai | browser-solve | 2026-03-06: Browser-solve verified. Kasada passthrough→200 6.1MB. Search redirects to /b/food-332. |
| `chewy.com/blue-buffalo-life-protection-formula/dp/37466` | Kasada + Akamai | browser-solve | 2026-03-06: Browser-solve verified. Akamai behavioral→browser→passthrough→200 5.0MB. Product page. |
| `realestate.com.au` | Kasada (server-side) | browser-solve | 2026-02-21: Browser-solve verified. 429→browser→CT+cookies→200 626KB. CT from ips.js (no ST), cookie auth. |
| `hyatt.com` | Kasada (server-side) | browser-solve | 2026-02-21: Browser-solve verified. 429→browser→CT+cookies→200 41KB. CT from ips.js (no ST), 43 cookies. |
| `scheels.com` | Kasada (client-side) | pass | 2026-02-21: 200 804KB via TLS. Kasada is client-side only |
| `vividseats.com` | Kasada (client-side) | pass | 2026-02-21: 200 343KB via TLS. No server-side enforcement |
| `footlocker.co.uk` | Kasada (client-side) | pass | 2026-02-21: 200 593KB via TLS. Kasada SDK in page but no server-side enforcement |
| `wizzair.com` | Kasada (unverified) | pass | 2026-02-21: 200 1.9MB via TLS (302→/en-gb→200). No Kasada markers found |
| `gql.twitch.tv/integrity` | Kasada (API, full CT+CD) | untested | 2026-02-23: Confirmed full Kasada flow (p.js from k.twitchcdn.net, /tl returns both CT+ST). Commercial solvers confirm CD required. API-style POST, not page-navigate. Listener captures CT+ST; blocked on x-kpsdk-h HMAC generation. |

### F5 Shape

| URL | Challenge Type | Status | Notes |
|---|---|---|---|
| `nordstrom.com` | F5 Shape | browser-solve | 2026-02-21: 200+istlWasHere detected, browser-solve → 42 cookies, E2E 407KB real page. 2026-07-27 on Chrome 150: 200/5.37MB via TLS in 10.6s. A deliberate 5-request category burst also stayed clean (all 200, 3-6MB each) -- **no istlWasHere interstitial**, so the solver is unexercised, not broken. |
| `target.com` | F5 Shape | pass | 2026-02-22: 200 342KB via TLS. Custom `ssx.mod.js`; no Shape markers found |

## Tier 4: Interactive CAPTCHA (press-and-hold, slider)

Requires browser solver with human-like mouse input.

### PerimeterX/HUMAN (Press-and-Hold)

| URL | Challenge Type | Status | Notes |
|---|---|---|---|
| `wayfair.com/v/account/authentication/login` | PX press-and-hold | pass | 2026-02-21: 200 318KB via TLS -PX not triggered on new URL. **SOLVED** 2026-02-20 on old /v/account/login. PX appId `PX3Vk96I6i`; also has DataDome. 2026-07-27 on Chrome 150: a deliberate 6-request burst across login + 5 category pages stayed clean (all 200, up to 3.9MB) -- **PX never challenged**, so the press-and-hold solver is unexercised, not broken. |
| `zillow.com` | PX press-and-hold | pass | 2026-02-21: 200 419KB via TLS -no PX challenge on homepage |
| `walmart.com/blocked` | PX press-and-hold | pass | 2026-02-21: 200 16KB via TLS -blocked page renders without PX challenge |
| `fanduel.com` | PX (very aggressive) | pass | 2026-02-21: 200 427KB via TLS -no markers on Canadian landing page |
| `goodrx.com` | PX | pass | 2026-02-21: 200 3.4MB via TLS |
| `bhphotovideo.com` | PX press-and-hold | pass | 2026-02-21: 200 159KB via TLS |
| `academy.com` | PX press-and-hold | pass | 2026-02-21: 200 855KB via TLS |
| `belk.com` | PX press-and-hold | pass | 2026-02-21: 200 1.4MB via TLS |
| `realtor.com` | Kasada | browser-solve | 2026-02-21: Browser-solve verified. 429→browser→kasada cookies→200 286KB. **Reclassified from PX to Kasada**. 2026-07-27: re-verified on system Chrome 150.0.7871.182 -- kasada detected→browser passthrough (31 cookies)→200 701KB in 7.7s; Kasada session stored (TTL 1800s). |
| `homedepot.com` | Akamai | browser-solve | 2026-02-21: Browser-solve verified. akamai challenge→browser→200 971KB. **Reclassified from PX to Akamai**. 2026-02-22: passed TLS-only (intermittent). 2026-07-27: re-verified on system Chrome 150.0.7871.182 -- `akamai behavioral` detected on body, rotations exhausted and session retired, then browser passthrough (22 cookies)→200 901KB in 6.0s. |
| `indeed.com` | PX | pass | 2026-02-21: 200 660KB via TLS |
| `priceline.com` | PX | pass | 2026-02-21: 200 625KB via TLS |
| `lanebryant.com` | PX | pass | 2026-02-21: 200 515KB via TLS |
| `thenorthface.com` | PX | pass | 2026-02-21: 200 724KB via TLS |
| `carters.com` | PX | pass | 2026-02-21: 200 498KB via TLS |
| `ralphlauren.com.au` | PX | pass | 2026-02-21: 200 750KB via TLS |
| `bkstr.com` | PX | pass | 2026-02-21: 200 31KB via TLS |
| `hibbett.com` | PX press-and-hold | blocked | 2026-02-21: PX challenge for TLS but browser passes without challenge → no _px3 cookie → cookie replay impossible. Sneaker retailer, aggressive PX config. (The original note blamed a burned IP; that is not an accepted explanation -- retest against a real headed browser and a fresh solver before trusting the `blocked` status.) |

### DataDome (WASM PoW)

DataDome shifted to VM fingerprint (`plv3`) + WASM PoW in Jan 2026, which auto-resolve in a real browser. If DD escalates beyond PoW (audio captcha, puzzle slider, slide-right), we cannot solve it - DD's behavioral analysis detects CDP-dispatched input events and rejects even correct answers. See `docs/ref-datadome.md`.

| URL | Challenge Type | Status | Notes |
|---|---|---|---|
| `pokemoncenter.com` | DataDome | pass | 2026-02-21: 200 698KB via TLS -no DD challenge on homepage |
| `etsy.com` | DataDome | browser-solve | 2026-02-21: Browser-solve verified. 403→browser→datadome cookie→200 238KB. 2026-02-22: passed TLS-only (intermittent) |
| `soundcloud.com` | DataDome | pass | 2026-02-21: 200 47KB via TLS |
| `seatgeek.com` | DataDome | pass | 2026-02-21: 200 838KB via TLS |

### Alibaba Baxia CAPTCHA

Alibaba's proprietary CAPTCHA (internal name: **Baxia**). Loaded via `baxiaCommon.js` from `assets.alicdn.com`. Slider mode (full-width drag, behavioral only) solved with mousse replay. `nc_` CSS prefix for NoCaptcha elements. See `docs/ref-baxia.md`.

| URL | Challenge Type | Status | Notes |
|---|---|---|---|
| `alibaba.com` | Alibaba Baxia/TMD | pass + browser-solve | 2026-07-27: **live-verified end to end on system Chrome 150.0.7871.182** (macOS, headed). A search burst triggered TMD on request 1; the browser solved the Baxia slider and returned 200 / 1.43MB of real results in 19.5s, then 11 consecutive 200s at ~2s each replaying the earned `x5sec`. Re-run after the navigation-budget fix: solved again, 12/12 200s. One run logged `Baxia result remained pending after release` and still succeeded -- widget state is an intermediate signal; the authoritative `x5sec` check is what decides. A single cold request usually passes with no challenge at all, so a burst is required to exercise the solver. **Headless verified too:** an 18-query burst solved on the first challenge and returned 18/18 200s, but only after the headless fingerprint patches were made to actually apply (they register via CDP and never execute under Patchright; now re-applied on navigation). While they were inert the slider still solved and earned no `x5sec` three rounds running. |
| `aliexpress.com` | Alibaba Baxia | pass (no challenge triggered) | 2026-07-27: cold search returned 200 / 704KB real results in 2.2s under a Chrome 150-pinned transport identity -- confirms the pinned UA/hints are accepted, but the Baxia solver was **not** exercised. Solver itself covered by the alibaba.com row. |
| `taobao.com` | Alibaba Baxia | browser-solve | Same Baxia backend; login-walled; Chinese IP required |

### GeeTest v4 Slide

GeeTest solver working (CV notch detection + mousse replay). 12/12 consecutive on demo. GeeTest loads dynamically in SPAs -need browser-level testing on real sites (navigate to login, submit form, observe if slide triggers).

| URL | Challenge Type | Status | Notes |
|---|---|---|---|
| `geetest.com/en/adaptive-captcha-demo` | GeeTest v4 slide | browser-solve | 2026-02-22: **SOLVED** 12/12+ consecutive. CV + mousse replay. **2026-07-27 re-verified on system Chrome 150.0.7871.182**: CV notch x=131 @ 0.940 confidence, drag replayed, `Drag puzzle solved!`, `solve_drag -> True in 10.6s`. **Trigger flow (the demo has no slide puzzle on load):** click `.tab-item` **nth(6)** = `Slide CAPTCHA`, wait ~3s, then click `.geetest_btn`. Do NOT use `text=Slide` -- it matches a nav menu entry and the click times out. |
| `bilibili.com` | Custom captcha | untested | 2026-02-22: **NOT GeeTest v4.** Custom captcha (`body__captcha-img_wp`). May have switched vendors. |
| `kucoin.com` | GeeTest v4 slide | pass | 2026-02-22: 200 394KB via TLS. No GeeTest triggered. SPA, may need form submission to trigger. |
| `aerlingus.com` | GeeTest v3 click | unverified | 2026-02-22: **GeeTest v3** (gt.js + fullpage.9.2.0), not v4. Click-to-verify, not slide puzzle. 84 geetest elements. |

### Other Slider/Puzzle CAPTCHAs

| URL | Challenge Type | Status | Notes |
|---|---|---|---|
| `jd.com` | JD/Tencent custom slider | no-drag | Signed XHR params; distinct slider mechanics |
| `shopee.com` | Shopee custom + CF puzzle | no-drag | 3 dedicated solver services exist for its CAPTCHA |
| `binance.com` | Custom slider CAPTCHA | no-drag | Trajectory analysis; open-source solver spawned 138-upvote post |

## Tier 5: Behavioral / In-House (continuous monitoring)

Requires browser with natural request patterns, sustained sessions, or account-level strategy. Often no generic solver is possible.

### Arkose Labs / FunCaptcha (no solver)

Wafer has **no Arkose Labs solver**. Arkose presents 3D puzzle CAPTCHAs (rotate, tile match, etc.) on login/signup flows. Used by Microsoft (Outlook, Xbox), Roblox, GitHub, EA, Twitter/X. The SDK loads from `<company>-api.arkoselabs.com/v2/<PUBLIC_KEY>/api.js`. Wafer can detect its presence but cannot solve the puzzles.

| URL | Challenge Type | Status | Notes |
|---|---|---|---|
| `outlook.live.com` | Arkose Labs | untested | Microsoft login; FunCaptcha on signup/recovery |
| `roblox.com` | Arkose Labs | untested | Login/signup flow; public key `9F35E182-C93C-...` |
| `github.com` | Arkose Labs | untested | Login flow; challenge on suspicious logins |
| `ea.com` | Arkose Labs | untested | EA account login |

### In-House Systems (no generic solver)

| URL | Challenge Type | Status | Notes |
|---|---|---|---|
| `google.com/search` | In-house (Google) | pass | 2026-02-21: 200 85KB via TLS -no challenge on basic search |
| `bing.com/search` | In-house (Microsoft) | pass | 2026-02-21: 200 119KB via TLS |
| `shein.com` | In-house (proprietary) | pass | 2026-02-21: 200 1.1MB via TLS |
| `linkedin.com` | In-house (Microsoft) | pass | 2026-02-21: 200 141KB via TLS -homepage renders without challenge |
| `instagram.com` | In-house (Meta) | pass | 2026-02-21: 200 663KB via TLS -landing page renders |
| `bet365.com` | In-house (custom) | pass | 2026-02-21: 200 40KB via TLS |
| `ssense.com` | Riskified | pass | 2026-02-21: 200 521KB via TLS |
| `tiktok.com` | In-house (custom VM) | pass | 2026-02-21: 200 306KB via TLS. Redirects to /explore. Custom VM-based anti-bot |
| `temu.com` | In-house (custom) | pass | 2026-02-21: 200 601KB via TLS. HMAC-signed headers on deeper pages |
| `reddit.com`, `old.reddit.com/*.json`, `api.reddit.com` | DataDome + in-house session gate | pass | 2026-07-26: Cold JSON requests can return a roughly 190 KiB Shreddit block page, while direct New Reddit HTML can return a small 200 verification document. Wafer recognizes both, performs the logged-out verification at `www.reddit.com` on the same client, validates response-scoped anonymous cookie evidence, persists durable cookie legs under one Reddit cache namespace, and replays the original JSON or HTML URL. Old Reddit remains available only when explicitly requested; it is never a bootstrap or fallback. **2026-07-28:** forced-inline-failure live verification recovered authoritative cookies at the fixed New Reddit root and replayed the original JSON request to 200 with zero rotations and no fingerprint pin. |
| `facebook.com/marketplace/` | In-house (Meta) | pass | 2026-02-21: 200 1.2MB via TLS. Login-walled for most data |
| `artists.spotify.com` | In-house (Spotify) | pass | 2026-02-21: 200 336KB via TLS. Redirects to /home. Login-walled |

### Other (CDN only, no WAF confirmed)

| URL | Challenge Type | Status | Notes |
|---|---|---|---|
| `canadagoose.com` | Kasada | browser-solve | 2026-02-21: Browser-solve verified. 429→browser→kasada cookies→200 568KB. **Reclassified from Yottaa CDN to Kasada** |
| `farfetch.com` | AWS CloudFront | pass | 2026-02-21: 200 350KB via TLS |
| `skyscanner.com` | None found | pass | 2026-02-21: 200 95KB via TLS |

---

## Coverage Summary

| WAF Vendor | Solver? | Verified Sites | What Works |
|---|---|---|---|
| **Cloudflare** (JS + Turnstile) | Yes | 17 | Browser solve with cookie replay or validated browser passthrough. |
| **Akamai** | Yes | 18 | Browser solve. Cookie replay difficult (_abck continuously validated). |
| **DataDome** | Partial | 17 | WASM PoW auto-resolve + confirm button + cookie replay. Match OS. Interactive challenges (slider, audio) are **unsolvable** - DD detects CDP input events. See `docs/ref-datadome.md`. |
| **PerimeterX** (press-and-hold) | Yes | 21 | Browser solve with recorded mouse input. **SOLVED** on wayfair. |
| **AWS WAF** | Yes | 6 | Browser solve for JS challenge. |
| **Imperva** | Yes | 6 | Browser solve + cookie replay. Handles modern reese84, legacy ___utmvc, and classic incap_ses. |
| **Kasada** | Yes | 9 | Browser solve extracts CT from ips.js/p.js. Cookie auth for simple deployments. Passthrough for dual-WAF (Chewy: Akamai+Kasada). CD PoW rewritten to match spec (hash chaining). |
| **F5 Shape** | Yes | 3 | Browser solve -passive wait for istlWasHere interstitial to clear. |
| **GeeTest v4** (slide) | Yes | 4 | Browser solve with CV notch detection + recorded mouse replay. **SOLVED** 12/12+ on demo. bilibili NOT GeeTest; aerlingus is GeeTest v3. |
| **hCaptcha** (checkbox) | Yes | 1 | Browser solve -checkbox click + token poll. Image escalation detected, not solved. |
| **reCAPTCHA v2** (checkbox + image grid) | Yes | 1 | Browser solve -checkbox click, image grid via ONNX classifier (dynamic 3x3 + static 3x3). Demo: `google.com/recaptcha/api2/demo`. **2026-07-27 live-verified on system Chrome 150.0.7871.182**: solved a real `dynamic_3x3` grid (keyword `bus`) on attempt 1 in 26.1s -- classifier scored all 9 tiles (3:0.974, 7:0.860, 6:0.581), all three clicks acknowledged, one dynamic-replacement round handled, Verify returned `statuses=200 classifications=protocol_solved`, token 2,340 chars. Note HTTP detection is gated on **403/429**, so a 200 page that merely embeds a widget is correctly not a challenge -- exercising the solver requires driving `wait_for_recaptcha` directly, as the demo returns 200. reCAPTCHA **v3** minting also verified: 2,105-char token in 0.4s, browser-free. |
| **Arkose Labs** (FunCaptcha) | **No** | 4 | 3D puzzle CAPTCHA on login flows. Microsoft, Roblox, GitHub, EA. |
| **Alibaba Baxia** | Yes | 2 | Browser solve with full-width drag + mousse replay. Live-tested on AliExpress. Real browser passes invisible check -interactive CAPTCHA hard to trigger externally. |
| **Chinese custom** (JD, Shopee) | **No** | 3 | Each has proprietary slider; needs per-vendor work. |
| **In-house** (Shein, LinkedIn, etc.) | **No** | 10 | No generic approach; each is unique. |

---

## Fingerprint Verification

### TLS (JA3/JA4)

| URL | What It Shows |
|---|---|
| `tls.peet.ws/api/all` | JA3, JA4, Akamai H2 fingerprint, full ClientHello |
| `tls.browserleaks.com/json` | TLS fingerprint data (clean JSON) |
| `scrapfly.io/web-scraping-tools/ja3-fingerprint` | JA3, JA4, comparison vs real browsers |
| `ja4db.com` | JA4 fingerprint database lookup |

### HTTP/2

| URL | What It Shows |
|---|---|
| `scrapfly.io/web-scraping-tools/http2-fingerprint` | SETTINGS, WINDOW_UPDATE, priority, pseudo-header order |
| `browserleaks.com/http2` | H2 SETTINGS and WINDOW_UPDATE |
| `browserscan.net/tls` | H2 + Akamai fingerprint + JA3/JA4 |

### Headers

| URL | What It Shows |
|---|---|
| `httpbin.org/headers` | Echo all headers exactly |
| `httpbin.org/anything` | Full request echo incl method, URL, args |

## Bot Detection Test Suites

| URL | What It Tests |
|---|---|
| `bot.incolumitas.com` | Comprehensive behavioral + fingerprint + proxy detection |
| `deviceandbrowserinfo.com/are_you_a_bot` | Browser/device signals (by Antoine Vastel) |
| `abrahamjuliot.github.io/creepjs/` | CreepJS: lie detection, cross-browser consistency |
| `browserscan.net/bot-detection` | WebDriver leaks, automation detection |
| `pixelscan.net` | Fingerprint consistency, UA mismatch |
| `bot-detector.rebrowser.net` | CDP detection, Runtime.enable leaks |
| `bot.sannysoft.com` | Classic WebDriver/headless detection |

## CAPTCHA Demo Pages

| System | URL |
|---|---|
| reCAPTCHA v2 | `google.com/recaptcha/api2/demo` |
| reCAPTCHA v3 | `2captcha.com/demo/recaptcha-v3` |
| hCaptcha | `accounts.hcaptcha.com/demo` |
| Cloudflare Turnstile | `developers.cloudflare.com/turnstile/troubleshooting/testing/` |
| GeeTest | `geetest.com/en/adaptive-captcha` |
| Alibaba CAPTCHA 2.0 | (no public demo; triggers on `aliexpress.com` login flow) |
