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
- `pass` -confirmed working via TLS only (rnet Emulation)
- `browser-solve` -needs browser solver, confirmed working
- `no-solver` -WAF vendor has no wafer solver yet (Kasada, F5 Shape, in-house)
- `no-drag` -needs drag/slider solver (not yet built)
- `untested` -not yet tested
- `unverified` -WAF claim not confirmed in latest smoke test (may trigger on deeper pages)
- `blocked` -IP/behavioral block, needs strategy change

---

## Tier 0: No Protection (baseline)

| URL | Challenge Type | Status | Notes |
|---|---|---|---|
| `httpbin.org/get` | None | pass | JSON with correct headers |
| `httpbin.org/headers` | None | pass | Echoes all headers |
| `httpbin.org/anything` | None | pass | Full request echo |
| `example.com` | None | pass | Static HTML |

## Tier 1: UA Check Only

Should pass with any Chrome Emulation profile.

| URL | Challenge Type | Status | Notes |
|---|---|---|---|
| `ticketmaster.com` | Akamai (lenient) | pass | Basic UA check |
| `nytimes.com` | Minimal | pass | Basic UA check, Datadog RUM only |

## Tier 2: TLS Fingerprint Required

Passes with rnet Chrome Emulation (JA3/JA4 + H2 fingerprint match).

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

## Tier 3: Browser Challenge (cookie solve + replay)

Requires browser solver for initial solve, then TLS client replays cached cookies.

### Cloudflare

| URL | Challenge Type | Status | Notes |
|---|---|---|---|
| `scrapingcourse.com/cloudflare-challenge` | CF + Turnstile | browser-solve | 2026-02-21: Browser-solve verified. 403→browser→cf_clearance→200 4KB |
| `scrapingcourse.com/antibot-challenge` | CF + Turnstile | browser-solve | 2026-02-21: Browser-solve verified. 403→browser→cf_clearance→200 4KB |
| `nowsecure.nl` | Cloudflare Turnstile | pass | 2026-02-21: 200 180KB via TLS -no challenge triggered |
| `hltv.org` | Cloudflare | pass | 2026-02-21: 200 421KB via TLS. CF CDN confirmed; challenge not triggered |
| `crunchbase.com` | Cloudflare | pass | 2026-02-21: 200 799KB via TLS. No CF challenge on homepage; login wall on company data |
| `capterra.com/categories` | Cloudflare | pass | 2026-02-21: 200 616KB via TLS |
| `fiverr.com` | Cloudflare | pass | 2026-02-21: 200 1.9MB via TLS |
| `miata.net` | Cloudflare | browser-solve | 2026-02-21: Browser-solve verified. 403→browser→cf_clearance→200 26KB |
| `glassdoor.com` | Cloudflare | pass | 2026-02-21: 200 648KB via TLS |
| `kick.com` | Cloudflare | browser-solve | 2026-02-21: Browser-solve verified. 403→browser→cf_clearance→200 502KB. **Reclassified from Kasada to Cloudflare** |
| `fbref.com` | Cloudflare | browser-solve | 2026-02-21: Browser-solve verified. 403→browser→cf_clearance→200 554KB. Sports reference |
| `manta.com` | Cloudflare | blocked | 2026-02-21: CF managed challenge (403 for TLS, 200 for browser). Browser passes without challenge → no cf_clearance issued → cookie replay impossible. **Reclassified from Imperva to Cloudflare**. Requires JS execution, not solvable via cookie replay |

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
| `amadeus.com` | Imperva (reese84) | pass | 2026-02-21: 200 183KB via TLS -no challenge on homepage. Previously required browser-solve |
| `anz.com.au` | Imperva (reese84) | pass | 2026-02-21: 200 323KB via TLS |
| `www.hkbea.com/html/en/index.html` | Imperva (incap_ses) | pass | 2026-02-22: 200 162KB via TLS. Bare `hkbea.com` DNS NXDomain -only `www.hkbea.com` resolves. |
| `appdev.pwc.com` | Imperva (___utmvc) | pass | 2026-02-21: 200 3KB via TLS -Imperva challenge not triggered |

### AWS WAF

| URL | Challenge Type | Status | Notes |
|---|---|---|---|
| `amazon.com` | AWS WAF JS challenge | browser-solve | 2026-02-21: Browser-solve verified. 202→browser→aws-waf-token→200 790KB. 2026-02-22: passed TLS-only (intermittent) |
| `booking.com` | AWS WAF | browser-solve | 2026-02-21: Browser-solve verified. 202→browser→200 487KB |
| `shutterstock.com` | DataDome | browser-solve | 2026-02-21: Browser-solve verified. 403→browser→datadome cookie→200 978KB. **Reclassified from AWS WAF to DataDome** |
| `stubhub.com` | AWS WAF | pass | 2026-02-21: 200 182KB via TLS |

### Kasada

Kasada solver: browser solve extracts CT token from ips.js/p.js response, cookies provide session auth. CD (proof-of-work) requires ST from /tl endpoint -not all deployments provide it.

**Validation gap**: No site found that returns `x-kpsdk-st`. The CT+CD per-request header injection path (`generate_cd()`) is unit-tested but has zero live validation. Both confirmed sites use cookie-only auth (no ST). Looking for a Kasada deployment with ST to validate the full flow -see `ref-kasada.md` "Open: ST/CD Flow Validation".

| URL | Challenge Type | Status | Notes |
|---|---|---|---|
| `realestate.com.au` | Kasada (server-side) | browser-solve | 2026-02-21: Browser-solve verified. 429→browser→CT+cookies→200 626KB. CT from ips.js (no ST), cookie auth. |
| `hyatt.com` | Kasada (server-side) | browser-solve | 2026-02-21: Browser-solve verified. 429→browser→CT+cookies→200 41KB. CT from ips.js (no ST), 43 cookies. |
| `scheels.com` | Kasada (client-side) | pass | 2026-02-21: 200 804KB via TLS. Kasada is client-side only |
| `vividseats.com` | Kasada (client-side) | pass | 2026-02-21: 200 343KB via TLS. No server-side enforcement |
| `footlocker.co.uk` | Kasada (client-side) | pass | 2026-02-21: 200 593KB via TLS. Kasada SDK in page but no server-side enforcement |
| `wizzair.com` | Kasada (unverified) | pass | 2026-02-21: 200 1.9MB via TLS (302→/en-gb→200). No Kasada markers found |
| `gql.twitch.tv/integrity` | Kasada (API, full CT+CD) | untested | 2026-02-23: Confirmed full Kasada flow (p.js from k.twitchcdn.net, /tl returns both CT+ST). Commercial solvers confirm CD required. API-style POST, not page-navigate. Needs browser solver extension to capture ST from /tl response. |

### F5 Shape

| URL | Challenge Type | Status | Notes |
|---|---|---|---|
| `nordstrom.com` | F5 Shape | browser-solve | 2026-02-21: 200+istlWasHere detected, browser-solve → 42 cookies, E2E 407KB real page |
| `target.com` | F5 Shape | pass | 2026-02-22: 200 342KB via TLS. Custom `ssx.mod.js`; no Shape markers found |

## Tier 4: Interactive CAPTCHA (press-and-hold, slider)

Requires browser solver with human-like mouse input.

### PerimeterX/HUMAN (Press-and-Hold)

| URL | Challenge Type | Status | Notes |
|---|---|---|---|
| `wayfair.com/v/account/authentication/login` | PX press-and-hold | pass | 2026-02-21: 200 318KB via TLS -PX not triggered on new URL. **SOLVED** 2026-02-20 on old /v/account/login. PX appId `PX3Vk96I6i`; also has DataDome |
| `zillow.com` | PX press-and-hold | pass | 2026-02-21: 200 419KB via TLS -no PX challenge on homepage |
| `walmart.com/blocked` | PX press-and-hold | pass | 2026-02-21: 200 16KB via TLS -blocked page renders without PX challenge |
| `fanduel.com` | PX (very aggressive) | pass | 2026-02-21: 200 427KB via TLS -no markers on Canadian landing page |
| `goodrx.com` | PX | pass | 2026-02-21: 200 3.4MB via TLS |
| `bhphotovideo.com` | PX press-and-hold | pass | 2026-02-21: 200 159KB via TLS |
| `academy.com` | PX press-and-hold | pass | 2026-02-21: 200 855KB via TLS |
| `belk.com` | PX press-and-hold | pass | 2026-02-21: 200 1.4MB via TLS |
| `realtor.com` | Kasada | browser-solve | 2026-02-21: Browser-solve verified. 429→browser→kasada cookies→200 286KB. **Reclassified from PX to Kasada** |
| `homedepot.com` | Akamai | browser-solve | 2026-02-21: Browser-solve verified. akamai challenge→browser→200 971KB. **Reclassified from PX to Akamai**. 2026-02-22: passed TLS-only (intermittent) |
| `indeed.com` | PX | pass | 2026-02-21: 200 660KB via TLS |
| `priceline.com` | PX | pass | 2026-02-21: 200 625KB via TLS |
| `lanebryant.com` | PX | pass | 2026-02-21: 200 515KB via TLS |
| `thenorthface.com` | PX | pass | 2026-02-21: 200 724KB via TLS |
| `carters.com` | PX | pass | 2026-02-21: 200 498KB via TLS |
| `ralphlauren.com.au` | PX | pass | 2026-02-21: 200 750KB via TLS |
| `bkstr.com` | PX | pass | 2026-02-21: 200 31KB via TLS |
| `hibbett.com` | PX press-and-hold | blocked | 2026-02-21: PX challenge for TLS but browser passes without challenge → no _px3 cookie → cookie replay impossible. IP burned during testing. Sneaker retailer, aggressive PX config |

### DataDome (slider + VM PoW)

DataDome shifted to VM fingerprint (`plv3`) + WASM PoW in Jan 2026, which auto-resolve in a real browser. A jigsaw puzzle slider (ArgoZhang/SliderCaptcha) may still appear on some deployments. Solver handles both: auto-resolve (no interaction) and puzzle slider (CV notch detection + mousse drag).

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
| `aliexpress.com` | Alibaba Baxia | browser-solve | 2026-02-22: Baxia SDK (`baxiaCommon.js`, `AWSC/awsc.js`) loads on all pages. Solver live-tested. Real browser often passes invisible check -interactive CAPTCHA triggers on rate-limiting or punish redirect. |
| `taobao.com` | Alibaba Baxia | browser-solve | Same Baxia backend; login-walled; Chinese IP required |

### GeeTest v4 Slide

GeeTest solver working (CV notch detection + mousse replay). 12/12 consecutive on demo. GeeTest loads dynamically in SPAs -need browser-level testing on real sites (navigate to login, submit form, observe if slide triggers).

| URL | Challenge Type | Status | Notes |
|---|---|---|---|
| `geetest.com/en/adaptive-captcha-demo` | GeeTest v4 slide | browser-solve | 2026-02-22: **SOLVED** 12/12+ consecutive. CV + mousse replay. |
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
| `reddit.com` | DataDome + in-house | pass | 2026-02-21: 200 621KB via TLS. DD not triggered on homepage; aggressive on old.reddit.com |
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
| **Cloudflare** (JS + Turnstile) | Yes | 15 | Browser solve + cookie replay. 30 min TTL. |
| **Akamai** | Yes | 18 | Browser solve. Cookie replay difficult (_abck continuously validated). |
| **DataDome** | Yes | 17 | Browser solve + cookie replay. Match OS. VM+PoW auto-resolves in browser. Puzzle slider solver ready (CV + mousse drag) if DD escalates. |
| **PerimeterX** (press-and-hold) | Yes | 21 | Browser solve with recorded mouse input. **SOLVED** on wayfair. |
| **AWS WAF** | Yes | 6 | Browser solve for JS challenge. |
| **Imperva** | Yes | 6 | Browser solve + cookie replay. Handles modern reese84, legacy ___utmvc, and classic incap_ses. |
| **Kasada** | Yes | 7 | Browser solve extracts CT from ips.js/p.js. Cookie-based auth confirmed on realestate.com.au. CD (PoW) needs ST from /tl. |
| **F5 Shape** | Yes | 3 | Browser solve -passive wait for istlWasHere interstitial to clear. |
| **GeeTest v4** (slide) | Yes | 4 | Browser solve with CV notch detection + recorded mouse replay. **SOLVED** 12/12+ on demo. bilibili NOT GeeTest; aerlingus is GeeTest v3. |
| **hCaptcha** (checkbox) | Yes | 1 | Browser solve -checkbox click + token poll. Image escalation detected, not solved. |
| **reCAPTCHA v2** (checkbox + image grid) | Yes | 1 | Browser solve -checkbox click, image grid via ONNX classifier (dynamic 3x3 + static 3x3). Demo: `google.com/recaptcha/api2/demo`. |
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
