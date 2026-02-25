# Sec-Fetch Reference

Reference for `Sec-Fetch-*` headers, embed mode header behavior, and WAF detection strategies for embedded requests.

## Exact Headers by Request Type (Chrome)

| Scenario | Sec-Fetch-Dest | Sec-Fetch-Mode | Sec-Fetch-Site | Sec-Fetch-User | Origin | X-Requested-With |
|---|---|---|---|---|---|---|
| Address bar / bookmark | `document` | `navigate` | `none` | `?1` | absent | absent |
| Same-origin link click | `document` | `navigate` | `same-origin` | `?1` | absent | absent |
| Cross-site link click | `document` | `navigate` | `cross-site` | `?1` | absent | absent |
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

## Accept Header by Request Type

| Request Type | Correct Accept Header |
|---|---|
| Top-level navigation | `text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9` |
| XHR/fetch for JSON | `*/*` or `application/json` (never the full navigation Accept) |
| Image subresource | `image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8` |
| Script subresource | `*/*` |

## Chrome Header Order (top-level navigation)

```
Host, Connection, Cache-Control, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform,
Upgrade-Insecure-Requests, User-Agent, Accept, Sec-Fetch-Site, Sec-Fetch-Mode,
Sec-Fetch-User, Sec-Fetch-Dest, Accept-Encoding, Accept-Language, Cookie
```

## Embed Mode Header Details

**XHR mode** sets: `Sec-Fetch-Mode: cors`, `Sec-Fetch-Dest: empty`, `Origin`, `Accept: */*`. Computes `Sec-Fetch-Site` from `embed_origin` vs request URL (`same-origin`, `same-site`, or `cross-site`). Strips navigation headers (`Cache-Control`, `Upgrade-Insecure-Requests`). Referer sends the full URL from `embed_referers`. No `X-Requested-With` -add it per-request for jQuery-style XHR: `headers={"X-Requested-With": "XMLHttpRequest"}`.

**Iframe mode** sets: `Sec-Fetch-Mode: navigate`, `Sec-Fetch-Dest: iframe`. Computes `Sec-Fetch-Site` (same as XHR). No `Origin` (GET navigations don't send it). Keeps navigation `Accept` and `Upgrade-Insecure-Requests`.

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
