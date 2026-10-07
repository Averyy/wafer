# TODO: post-solve passthrough returns the script-mutated DOM, not the server's document

**Owner:** wafer
**Status:** OPEN. Found from fetchaller on 2026-10-07, wafer 0.7.2. No wafer
code changed; this note is the hand-off.
**Reported by:** fetchaller (re-test after the 0.7.2 upgrade)

---

## Symptom

fetchaller fetched a homedepot.com article (`/c/ab/...`) on a cold cache. wafer
solved Akamai's behavioural challenge, which is new in 0.7.2 and works. The
rendered page then opened with JavaScript source as its first paragraph:

```
# Choose the Best Drill Bits for Your Next Project - The Home Depot

Object.defineProperty(document, "referrer", {get : function(){ return ""; }})
```

A second read of the same URL is a plain replay on the earned cookies. It is
clean, so the same URL renders differently cold and warm.

## Cause

The post-solve passthrough in `BrowserSolver` (`wafer/browser/_solver.py`, the
`_bounded_page_content(page, max_size)` loop around lines 5310-5370) builds
`CapturedResponse.body` from `page.content()`. `AsyncSession` then returns that
as the body of `session.get()` (`wafer/_async.py` around line 1117, "Browser
passthrough").

`page.content()` serializes the **live DOM after the page's scripts ran**, which
is not what the server sent. On homedepot.com, a script inserts PerimeterX's
loader as a child element *inside* an existing inline `<script>`. That
serializes as:

```html
<script type="text/javascript"><script async="" src="//client.px-cloud.net/PXJ770cP7Y/main.min.js"></script>Object.defineProperty(document, "referrer", {get : function(){ return ""; }})</script>
```

That markup does not round-trip. Every HTML parser, browsers included, ends the
outer `<script>` at the first `</script>`, so the inline code becomes a text
node. Any consumer that parses the body (BeautifulSoup, lxml, markdownify)
shows it as page text.

## Evidence (same session, same URL)

| read | status | `was_retried` | chars | nested script | `px-cloud` `<script>` element |
|---|---|---|---|---|---|
| first (solve, passthrough) | 200 | True | 903,832 | yes, at offset 422,727 | yes |
| second (plain replay) | 200 | False | 895,743 | no | no (only `preconnect`/`dns-prefetch` links) |

The server's document contains neither the `Object.defineProperty(document,
"referrer"...)` script nor a `client.px-cloud.net/.../main.min.js` script
element. Both were added at runtime. The replay also shows that cookie replay
works for this site, so a passthrough was not needed to get content.

The passthrough's `CapturedResponse` headers are synthetic too:
`{"content-type": "text/html; charset=utf-8"}`, with status
`landed_status or 200`.

## Why it matters beyond Home Depot

Any passthrough body is the DOM after JavaScript has run: injected trackers,
hydrated or removed nodes, rewritten attributes. A caller cannot tell it from
the server's bytes, and the same URL answers with different documents cold and
warm. This one surfaced only because the mutation produced markup that does not
round-trip. Quieter changes, such as client-side rendered content appearing or
server content being removed, would pass unnoticed.

## Possible directions (for the wafer dev to judge)

1. Return the main document's **network** response body, not
   `page.content()`. `main_documents` already tracks the main-document
   responses by URL for their status, so `response.body()` / CDP
   `Network.getResponseBody` for the landed URL's last main-document response
   gives the server's bytes and real headers. That has to be the response for
   the post-challenge reload, not the interstitial.
2. Where cookie replay is known to work for the challenge type (it did for
   Akamai behavioural here), replay through the transport instead of passing
   the page through, and keep passthrough for TLS-bound clearance only. The
   code comment already scopes passthrough to "when cookie replay is
   unreliable (TLS-bound)", but the loop runs for every challenge type except
   TMD.

fetchaller has not added a workaround. It renders the HTML it is given, and a
browser parsing those same bytes shows the same text. The document has to be
right at the source.

## Repro

```python
import asyncio, tempfile
from wafer import AsyncSession
from wafer.browser import BrowserSolver

URL = "https://www.homedepot.com/c/ab/drill-bit-buying-guide/9ba683603be9fa5395fab9026af9044"
NEEDLE = '<script type="text/javascript"><script async=""'

async def main():
    s = AsyncSession(browser_solver=BrowserSolver(), cache_dir=tempfile.mkdtemp())
    first = await s.get(URL, timeout=120)    # cold: Akamai solve, passthrough
    second = await s.get(URL, timeout=60)    # warm: plain replay
    print(first.was_retried, NEEDLE in first.text)    # True True
    print(second.was_retried, NEEDLE in second.text)  # False False

if __name__ == "__main__":
    asyncio.run(main())
```
