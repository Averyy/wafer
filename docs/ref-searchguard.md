# Google SearchGuard

## Status

For a separately validated browserless Google web-search route, see
[Docs research search](ref-google-research.md). It returned general-web and
Reddit results with distinct second pages using stock curl and wafer's core
dependencies. It requires no impersonation, JavaScript runtime, browser, login,
or wafer upgrade. The [fetchaller handoff](google-search-fetchaller-handoff.md)
and [verified document pool](google-search-document-pool.json) describe that
working API route. `/search` SearchGuard acceptance below remains unconfirmed.

The Opera Mini server-rendered route is closed. Wafer now has a browserless
SearchGuard solver using QuickJS-NG from the `[browser]` extra. It runs the
first four inline scripts from the SearchGuard shell in a bounded context
(memory, CPU time, and stack), captures the short-lived `SG_SS` cookie, and
validates Google's same-host `/search` URL containing `sei` before replaying
it. It does not launch a browser.

Offline execution against a captured shell generated both expected outputs.
Later offline record recovery showed that output generation can also succeed
when the VM has encoded an internal exception. The shim now covers the missing
iframe built-ins, Location fields, DOM methods, prototype accessors, and event
option conversion identified in those runs, and preserves QuickJS-NG's native
high-resolution clock. The older saved shell emits a report without embedded
exceptions after those changes; newly captured mobile programs still expose
other environment differences. A cookie alone is not evidence of acceptance.
Google acceptance remains unconfirmed. A same-session replay of the exact
`sei` handoff ended at a 429 `/sorry` reCAPTCHA response. Follow-up wafer
probes used session-level `follow_redirects=False`; Google returned HTTP 302
from `/search` to `/sorry/index` for three different queries, a search after
loading the homepage, `google.ca`, and a Firefox 152 identity. No redirect
target was requested, and those probes did not reach the SearchGuard shell or
results. A later page-2 probe did reach the shell, ran one inline solve, and
then received a 302 to `/sorry` on the `sei` handoff. That target was not
fetched either. No results have been observed through this SearchGuard solver.
These observations do not distinguish a rejected SearchGuard token from a
separate risk challenge. Do not follow `/sorry`: fetching it triggers a
CAPTCHA request.

## Measured behavior

The earlier identity and endpoint measurements below were made from wafer on
the project's own network, one request at a time with at least six seconds
between requests. Follow-up probes are listed separately; each used
`follow_redirects=False` and did not fetch `/sorry`.

| Request identity or flow | Observation |
|---|---|
| Opera Mini UA versions 83.1, 90, 98, 105, 110 | HTTP 403 with the same 1,661-byte body |
| Opera Mini header variants, Presto UA alone, alternate query params, home-page form flow, alternate Google country domains | HTTP 403 |
| Other legacy mobile identities (J2ME Opera Mini, Opera Mobi, Opera Mini iOS, Android 4 stock, NetFront) | HTTP 403 |
| Lynx and IE6 | Small unsupported-browser page |
| Firefox 52, desktop Presto, current Chrome/mobile Chrome, Chrome with `OPR/`, UCWEB, curl | HTTP 200 SearchGuard shell, no server-rendered results |
| `/search?gbv=1`, `/xhtml`, `/m`, `/m/search`, `/custom`, search verticals | Same shell or unsupported-browser page |
| Browserless Chrome queries `wafer python http client`, `best way to brew coffee`, and `site:python.org asyncio documentation`, redirects disabled | Each HTTP 302 from `/search` to `/sorry/index`; no target fetched |
| Homepage first, then `python asyncio documentation` in the same session | Homepage HTTP 200; search HTTP 302 to `/sorry/index`; target not fetched |
| `google.ca` query `wafer Python package` | HTTP 302 to `google.com/sorry/index`; target not fetched |
| Firefox 152 query `wafer Python package` | HTTP 302 from `/search` to `/sorry/index`; target not fetched |
| Chrome page-2 query with `start=10&num=10` | SearchGuard shell, one QuickJS solve, then HTTP 302 to `/sorry` on `sei` replay; target not fetched |
| Chrome page-2 query on `google.co.uk` | SearchGuard shell, one QuickJS solve, then HTTP 302 to `/sorry` on `sei` replay; target not fetched |

The shell contains a `<noscript>` redirect to
`/httpservice/retry/enablejs`, a `knitsail` bootstrap, encrypted challenge
data, and an obfuscated interpreter. On success, its JavaScript writes a
short-lived `SG_SS` cookie and reloads `/search`. Reimplementing the VM in
Python would be brittle because the challenge data and VM rotate.

The solver executes the rotating VM rather than decoding it. Its output is
accepted only when it contains an `SG_SS` cookie and a handoff to the same
HTTPS hostname's `/search` path with a nonempty `sei` value. The cookie is
scoped to the challenged URL, has `Max-Age=30`, and is not persisted to disk.
The retry paths pass the request's actual User-Agent to the VM, including a
per-request override. A local HTTPS server confirmed that wreq transmits the
Secure cookie on the handoff URL; Google acceptance remains unconfirmed.
An independent browserless replay with a Node VM harness and a separate
iframe realm also reached `/sorry` after the `sei` handoff. That comparison
does not isolate the field or risk signal behind Google's decision.
The `sei` replay now uses the shell URL as Referer and removes
`Sec-Fetch-User` for Chromium, matching a script-initiated navigation. A local
TLS echo verified those headers and the Secure cookie on the same request.
The subsequent CAPTCHA-safe live replay still redirected to `/sorry`.
For Chromium, the handoff also replaces a caller's initial Referer and fetch
metadata with those of the new script navigation, preserving other per-request
overrides. Other profiles also update the handoff Referer.
The Node VM comparison also redirected there when repeated with these headers.
Fresh homepage form submissions, with and without loading its external
scripts, also reached SearchGuard and redirected to `/sorry` after the
handoff. An offline VM probe against a current saved shell showed that it
collects navigator, screen, history, viewport, performance, and Chrome
globals. The QuickJS shim now supplies basic versions of those values, but
its live handoff still redirected to `/sorry`. Google acceptance remains
unverified.
The server deletes `SG_SS` with a 1990 expiry on the `/sorry` redirect, but a
[published successful pass](https://shlomishabat.github.io/articles/botguard-interstitial.html)
also shows that deletion. A controlled replay with the same `sei` URL and
headers but no `SG_SS` returned another SearchGuard shell. The proof changes
the server's path; these observations do not show whether the report failed
validation or whether a later risk check requested CAPTCHA. The homepage also
sets JS-readable `__Secure-STRP` and `SEARCH_SAMESITE` cookies; the solver now
supplies scoped, non-HttpOnly cookies to its `document.cookie` shim.
The QuickJS context has no network or filesystem bridge; its DOM shim covers
the APIs observed in the shell. If the VM changes beyond that surface, times
out, or returns malformed output, the solver declines and the normal browser
fallback/error handling applies.

QuickJS-NG is installed by the existing `[browser]` extra because the project
has only core and browser/advanced-solver install modes. Despite the extra's
name, this path does not open or require a browser.

## Browser path

A headed `BrowserSolver` run executed the shell and produced a results DOM.
An automatic transport retry then got Google's `/sorry` reCAPTCHA (HTTP 429);
the existing browser reCAPTCHA solver accepted it and the overall
`session.get()` returned HTTP 200 with result containers. This is a distinct
browser path.

The already documented `session.render()` route remains available. Do not
describe Opera Mini as a Google SSR workaround. Space live probes by at least
six seconds; do not repeat a failed request method rapidly. Never follow a
`/sorry` redirect: `/sorry` is a CAPTCHA request, not a harmless failed probe.

## Retired coverage

`tests/live_opera_mini.py` no longer sends Google Search requests. Its former
`TestGoogleSSR` assertions were stale and could trigger the separate `/sorry`
reCAPTCHA flow. Opera Mini remains covered against DuckDuckGo and other
non-Google routes. Browserless SearchGuard code remains unvalidated against
successful Google results and pagination until the exact handoff reaches those
pages.
