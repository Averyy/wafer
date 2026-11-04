# Akamai Bot Manager

Akamai answers a request it distrusts in several shapes. wafer detects each in
`wafer/_challenge.py` and classifies all of them `akamai`; one is answered
inline over the transport, the rest go to the browser (`wafer/browser/_akamai.py`,
`wait_for_akamai`).

## Status

| Shape | Seen on | Detection | Solving |
|---|---|---|---|
| bm-verify interstitial: 200, about 2.2 KB, posts a token and a proof of work | www.amazon.co.uk | `is_akamai_interstitial` (body, any status) | **Inline**, no browser (`parse_akamai_interstitial`) |
| Script refusal: small 403/429 "Error Page" that sets `bm_s`/`bm_so` and loads `/<random>?v=<uuid>` | www.ebay.ca, homedepot.com | Set-Cookie `bm_so`/`sbsd_o` on a 403/429 (header fast path) | Browser: one retried navigation after the script posts |
| Behavioral challenge (`sec-if-cpt`, `behavioral-content`) | homedepot.com, chewy.com | Body markers, with or without `_abck` | Browser |
| Sensor challenge (`_abck` + `bmSz` / `sensor_data`) | various | Set-Cookie + body markers on a non-200 | Browser |

## bm-verify interstitial

Measured 2026-11-03 from the plain client in a Linux image (5 of 8 cold
`GET https://www.amazon.co.uk/s?k=usb+c+cable`; the others drew AWS WAF).
The response is a **200** from `server: AkamaiGHost`, setting `ak_bmsc`
(`Domain=.amazon.co.uk`, `Max-Age=7200`), with this body (tokens trimmed;
full copy in `tests/fixtures/amazon_akamai_interstitial_2026-11-03.html`):

```html
<meta http-equiv="refresh" content="5; URL='/s?k=usb+c+cable&amp;ref=nb_sb_noss&bm-verify=AAQAAAAO_____...'" />
<script> var i = 1793762341; var j = i + Number("1251" + "02029"); </script>
...
xhr.open("POST", "/_sec/verify?provider=interstitial", false);
xhr.setRequestHeader("Content-Type", "application/json");
xhr.send(JSON.stringify({"bm-verify": "AAQAAAAO/////...", "pow": j}));
```

The answer is JSON: `{"reload": true}` means reload the URL without its
`bm-verify` parameter, `{"location": ...}` means go there, and anything else
makes the script reload. No sensor script runs on the page.

**What wafer does.** `is_akamai_interstitial` keys on structure: under 20 KB,
the `/_sec/verify?provider=interstitial` endpoint, a `bm-verify` token, and
the `var i = ...; var j = i + Number("..." + "...")` arithmetic. A page that
quotes it inside a larger document is not detected. The session's inline
solver (`_try_inline_solve`, sync and async) makes the script's POST over the
transport: the JSON `{"bm-verify":token,"pow":i + int(a + b)}` as
`JSON.stringify` writes it (the script's `Number(a + b)` concatenates the
digit strings), shaped as the page's XHR: `Accept: */*`, `Content-Type`,
`Origin`, `Referer`, `Sec-Fetch-Mode: cors`, `Sec-Fetch-Dest: empty`,
`Sec-Fetch-Site`, `Priority: u=1, i`, in Chrome's captured fetch() order
(`docs/ref-sec-fetch.md`), with wreq's navigation defaults off so neither
`Upgrade-Insecure-Requests` nor `Sec-Fetch-User` rides along
(`BaseSession._page_xhr_headers`). Its cookies go into the jar, and the
request is replayed: on the URL without `bm-verify`, or on a `location` the
answer names when it is on the same origin.

The shape of that POST matters. Sent with the navigation client's headers
(its `Upgrade-Insecure-Requests` and `Sec-Fetch-User`, navigation order), it
still answered `200 {"reload": true}` with a fresh `ak_bmsc` in 0.07s, but
the replay drew Amazon's own `503 Service Unavailable` page 2 of 4 (results
2 of 4). Shaped as the XHR above, the replay returned the search page 3 of 3
(1.33-1.49 MB, the whole request about 2s), 2026-11-03.

How often it appears varies: 5 of 8 cold requests early on 2026-11-03, all
claiming Chrome 154 (wafer before it presented 157); later 1 of 7 claiming
154 and 0 of 9 claiming 157, AWS WAF's challenge every other time.

## Script refusal and the claimed version

The refusal page is Akamai declining the request before any sensor runs; once
its script has posted, the same navigation goes through, which is why the
browser handler retries the navigation once (and gives up about 15s after a
refusal that survives it).

What draws it is the request itself, and two cases measured 2026-11-03 show
how specific that is:

- **homedepot.com refused a header order.** wafer's browser sent
  `Accept-Language` right after `User-Agent` (the CDP user-agent override's
  `acceptLanguage` does that), an order no stock Chrome has. Refused from
  Linux 3 of 3 and Windows 1 of 1, let through from macOS; the natural order
  got the solvable behavioral page on all three. Fixed by setting the
  languages with `--accept-lang` instead (see `docs/ref-headless.md`).
- **www.ebay.ca weighed an outdated Chrome from Linux.** From fetchaller's
  Linux image, alternating cold requests from the plain client minutes
  apart: claiming Chrome 154, refused 3 of 3; claiming 157, then current
  stable, results 3 of 3, with identical TLS and HTTP/2. Stock Google Chrome
  stable 157 in the image was served 3 of 3, stock Chrome for Testing 154 was
  refused. macOS was served either version. The verdict also moves with
  other state: about an hour and many requests later, both claims were
  refused (or got eBay's splash, as stock Chrome did), and after a 45-minute
  pause both were served (154 1 of 1, 157 2 of 2, stock Chrome 1 of 1). wafer
  now presents the current stable release over the newest wreq profile when
  its wire is identical (`_WIRE_IDENTICAL_RELEASES` in
  `wafer/_fingerprint.py`).

**In `render()`.** The refusal is classified with its document's own
headers, as the transport path classifies it, so render runs this handler
too; with status and body alone it read as `generic_js`, whose wait
re-navigated the page and then polled the refusal through render's 30s
post-solve window. When the retry goes on to the requested page (on eBay,
through its splash to the results), render keeps that page rather than
navigating again: a second navigation is a fresh request for a verdict, and
eBay refused it (403). From fetchaller's Linux image (amd64 under emulation,
Chrome for Testing 157), 15 renders of an eBay search on 2026-11-04 all drew
the refusal first; 10 went through to the results after the retry (17-26s),
5 were refused again and reported as the challenge at about 22s.

To find such a cause, capture the refused client's and stock **Google Chrome
stable**'s wire at tls.peet.ws in the same environment (Chrome for Testing is
not what users run), then change one thing at a time from the plain client:
platform, header order, claimed version.
