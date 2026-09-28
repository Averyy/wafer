# Sec-Fetch Reference

Reference for `Sec-Fetch-*` headers, embed mode header behavior, and WAF detection strategies for embedded requests.

## Exact Headers by Request Type (Chrome)

| Scenario | Sec-Fetch-Dest | Sec-Fetch-Mode | Sec-Fetch-Site | Sec-Fetch-User | Origin | X-Requested-With |
|---|---|---|---|---|---|---|
| Address bar / bookmark | `document` | `navigate` | `none` | `?1` | absent | absent |
| Same-origin link click | `document` | `navigate` | `same-origin` | `?1` | absent | absent |
| Cross-site link click | `document` | `navigate` | `cross-site` | `?1` | absent | absent |
| Script-submitted form / `location=` (no user activation) | `document` | `navigate` | relation to the page | absent | absent (GET) | absent |
| iframe (cross-origin) | `iframe` | `navigate` | `cross-site` | absent | absent | absent |
| iframe (same-origin) | `iframe` | `navigate` | `same-origin` | absent | absent | absent |
| Script tag (CDN) | `script` | `no-cors` | `cross-site` | absent | absent | absent |
| XHR same-origin | `empty` | `same-origin` | `same-origin` | absent | absent | only if explicitly set |
| XHR cross-origin CORS | `empty` | `cors` | `cross-site` | absent | present | only if explicitly set |
| fetch() cross-origin | `empty` | `cors` | `cross-site` | absent | present | absent |
| fetch() same-origin | `empty` | `same-origin` | `same-origin` | absent | absent | absent |
| embed element | `embed` | `navigate` | varies | absent | absent | absent |

## Invalid Combinations (instant bot flags)

| Combination | Why It's Impossible |
|---|---|
| `Dest: empty` + `Mode: cors` + `User: ?1` | User is only sent on navigate mode |
| `Dest: document` + `Mode: cors` | Document destination implies navigate mode |
| `Dest: empty` + `Mode: navigate` | Navigate implies document/iframe/frame/embed/object dest |
| `Dest: script` + `Mode: navigate` | Scripts don't navigate |
| `Dest: iframe` + `Mode: cors` | iframes use navigate mode |
| `Site: none` + a `Referer` | `none` means no page started the navigation (typed URL, bookmark), and such a navigation has no referrer |

## Accept Header by Request Type

| Request Type | Correct Accept Header |
|---|---|
| Top-level navigation | `text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7` |
| XHR/fetch for JSON | `*/*` or `application/json` (never the full navigation Accept) |
| Image subresource | `image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8` |
| Script subresource | `*/*` |

## Chrome Header Order (top-level navigation)

```
Content-Length, Cache-Control, sec-ch-ua, sec-ch-ua-mobile,
[sec-ch-ua-full-version, sec-ch-ua-arch], sec-ch-ua-platform,
[sec-ch-ua-platform-version, sec-ch-ua-model, sec-ch-ua-bitness,
sec-ch-ua-full-version-list], Upgrade-Insecure-Requests, Content-Type,
User-Agent, Origin, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-User,
Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie, Priority
```

Captured 2026-09-27 from Google Chrome 153 (`_fingerprint._CHROMIUM_NAVIGATION_ORDER`,
which wafer applies to Chrome and Edge navigations). `Content-Length`,
`Cache-Control: max-age=0`, `Content-Type` and `Origin` appear only on a form
POST. The bracketed high-entropy hints appear only after the origin asked for
them with `Accept-CH`, and only those it asked for; a `Critical-CH` response
makes Chrome resend once with them. A plain navigation sends no
`Cache-Control`.

## wafer's navigations

- The first request to a host is an address-bar navigation (`none`, `?1`, no
  Referer).
- Later requests carry the automatic Referer (the last URL fetched on that
  host) with `Sec-Fetch-Site: same-origin` (a link click). A caller's Referer
  sets the relation the same way (PSL-lite aware); a caller's
  `Sec-Fetch-Site` is kept. Profiles without Fetch Metadata (Dart, OkHttp,
  Safari before 16.4) get none. Before 2026-09-27 wafer sent the Referer beside
  `none`, an impossible combination.
- Reddit's verification form goes out as its script submits it: `same-origin`,
  `Referer: https://www.reddit.com/`, no `Sec-Fetch-User` (Chrome 153 capture;
  see `docs/ref-reddit.md`).

## Embed Mode Header Details

In every embed mode wafer supplies the whole header set and its order itself, with wreq's per-profile headers turned off (`Emulation(..., headers=False)` + `orig_headers`). Those defaults are a top-level navigation, and since wreq 0.12.2 they carry `Sec-Fetch-User: ?1` and `Upgrade-Insecure-Requests: 1`, which wreq cannot drop individually. Left on, XHR mode sent the first row of the invalid-combination table above. The shapes below apply to desktop Chrome, Edge and Firefox emulations. wafer's Safari and iOS Safari identities already send only wafer's headers (Dart refuses embed mode). Any other `Emulation`, including a `fingerprint_pool` entry, is refused with `ValueError`, since wreq cannot drop its navigation headers.

**XHR mode** (`embed="xhr"`) sets: `Sec-Fetch-Mode: cors`, `Sec-Fetch-Dest: empty`, `Accept: */*`, and `Origin` except on a same-origin GET/HEAD (Fetch spec; Chrome's same-origin `fetch()` GET has none). Computes `Sec-Fetch-Site` from `embed_origin` vs request URL (`same-origin`, `same-site`, or `cross-site`). No navigation headers (`Cache-Control`, `Upgrade-Insecure-Requests`, `Sec-Fetch-User`). `Priority: u=1, i` (Chrome) / `u=4` (Firefox). Referer sends the full URL from `embed_referers`. No `X-Requested-With` (modern `fetch()` doesn't send it).

**jQuery XHR mode** (`embed="xhr-jquery"`) is identical to XHR mode plus the two markers a legacy jQuery `$.ajax` / `XMLHttpRequest` call adds: `X-Requested-With: XMLHttpRequest` and `Accept: application/json, text/javascript, */*; q=0.01` (the jQuery Accept, replacing `*/*`). Both are set at the client level (no HTTP/2 header duplication). Use this when an older `/ajax`, `getData`, tile, or autocomplete endpoint requires `X-Requested-With`; use plain `"xhr"` for modern `fetch()` endpoints. Firefox sends no `Priority` header on an `XMLHttpRequest`.

**Iframe mode** (`embed="iframe"`) sets: `Sec-Fetch-Mode: navigate`, `Sec-Fetch-Dest: iframe`. Computes `Sec-Fetch-Site` (same as XHR). No `Origin` (GET navigations don't send it; POST/PUT/PATCH/DELETE navigations do). Keeps navigation `Accept` and `Upgrade-Insecure-Requests`; Chrome adds `Cache-Control: max-age=0` only on a form POST. It is an embed loaded with the page, so no `Sec-Fetch-User` (that needs user activation). A cross-site load adds `Sec-Fetch-Storage-Access`: `active` for Chrome (third-party cookies allowed by default), `none` for Firefox (Total Cookie Protection). `Priority: u=0, i` (Chrome) / `u=4` (Firefox).

### Embed header order (captured)

Captured 2026-09-24 from Google Chrome 153.0.8010.53 and Firefox 153, each running a real `fetch()`, jQuery-style `XMLHttpRequest` and script-inserted iframe, GET and POST, with a cookie set (`_fingerprint._EMBED_HEADER_ORDER`). Absent headers are skipped. wafer's high-entropy client hints follow at the end.

| Mode | Chrome / Edge | Firefox |
|---|---|---|
| `xhr` | content-length, sec-ch-ua-platform, user-agent, sec-ch-ua, content-type, sec-ch-ua-mobile, accept, origin, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority | user-agent, accept, accept-language, accept-encoding, referer, content-type, content-length, origin, cookie, sec-fetch-dest, sec-fetch-mode, sec-fetch-site, priority, te |
| `xhr-jquery` | content-length, sec-ch-ua-platform, x-requested-with, user-agent, accept, sec-ch-ua, content-type, sec-ch-ua-mobile, origin, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority | user-agent, accept, accept-language, accept-encoding, content-type, x-requested-with, content-length, origin, referer, cookie, sec-fetch-dest, sec-fetch-mode, sec-fetch-site, te |
| `iframe` | content-length, cache-control, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, upgrade-insecure-requests, content-type, user-agent, origin, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, sec-fetch-storage-access, referer, accept-encoding, accept-language, cookie, priority | user-agent, accept, accept-language, accept-encoding, sec-fetch-storage-access, content-type, content-length, origin, referer, cookie, upgrade-insecure-requests, sec-fetch-dest, sec-fetch-mode, sec-fetch-site, priority, te |

The Firefox captures used Playwright's Firefox 153 build, whose TLS and Accept-Language prefs are not stock, so only its order is used; values come from wafer's Firefox envelope.

### Same-site computation (PSL-lite)

`Sec-Fetch-Site: same-site` is computed by comparing the **registrable domain** of `embed_origin` against the request URL's host, using a curated public-suffix list (`wafer/_psl.py`) rather than a naive "last two labels" (TLD+1) heuristic. So two unrelated siblings under a multi-label public suffix -`a.co.uk` vs `b.co.uk`, `alice.github.io` vs `bob.github.io`, `x.com.au` vs `y.com.au` -are correctly classified **cross-site**, not same-site. The list is a hand-picked subset (country second-levels and popular hosting suffixes), intentionally incomplete: an *unlisted* multi-label suffix degrades gracefully to the old TLD+1 behavior (it never raises). The same PSL-lite backs cookie-domain matching (`get_cookie`/`add_cookie`). Override per-request if needed: `headers={"Sec-Fetch-Site": "cross-site"}`. Expand `wafer/_psl._MULTI_LABEL_SUFFIXES` to close a specific gap.

## WAF Detection Layers for Embed Requests

1. **Header consistency** -Cross-validate Sec-Fetch-* combinations, sec-ch-ua vs TLS fingerprint, header order vs claimed browser.
2. **TLS fingerprint correlation** -JA4+ fingerprinting. Headers claim Chrome but TLS matches Python/OpenSSL = instant detection.
3. **Session sequence analysis** -WAFs expect navigation -> subresources -> XHR. XHR without prior navigation is anomalous.
4. **Cookie state** -Legitimate embed requests arrive with cookies from prior navigation. XHR without session cookies is suspicious.
5. **CORS preflight expectation** -Cross-origin POST with custom headers must be preceded by OPTIONS. Missing preflight = non-browser.
6. **Origin validation** -Some WAFs maintain allowlists of known embed partners.
7. **Frame-ancestors/CSP cross-reference** -If site sends `frame-ancestors 'none'` but WAF sees `Sec-Fetch-Dest: iframe`, those aren't legitimate iframes.

## WebView Evasion (potential future technique)

Android/iOS WebViews often omit all Sec-Fetch-* and Client Hints headers. WAFs can't flag "missing Sec-Fetch = bot" because legitimate WebView traffic looks identical. Trades desktop Chrome impersonation for mobile WebView impersonation.

This "omit Sec-Fetch to look like a non-browser client" insight is **already realized** for Imperva: TLS-fingerprinting sites (e.g. `api2.realtor.ca`) challenge every BoringSSL browser-emulation but free-pass a plain OpenSSL client that sends no `Sec-Fetch-*`. wafer's native-TLS fallback (`wafer/_native_tls.py`, `docs/ref-imperva.md`) does exactly that -OpenSSL TLS + minimal headers, no `Sec-Fetch-*`/`Sec-Ch-Ua`. The flip side of layer 2 above: it works precisely *because* the request no longer claims to be Chrome, so the Chrome-vs-OpenSSL TLS mismatch isn't a contradiction.
