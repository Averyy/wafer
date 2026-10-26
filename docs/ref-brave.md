# Brave Search proof of work

Brave Search's first-party Argon2id/blind-token gate is `challenge_type="brave"`.
It is separate from wafer's inline SHA-256 `pow` gate. The fix is intended for
**0.7.9** (current published/tagged baseline: 0.7.8); no release is made by
editing this document.

## Detection

The 2026-10-25 real HTTP 429 capture is 73,896 characters, above the old generic
JS detector's 50 KB ceiling. The dedicated detector requires the exact HTTPS
`search.brave.com` origin and `/search` or `/captcha`, then either:

- an actual Svelte bootstrap script containing the internal `/captcha` route
  and an issued `challengeSet` object with `set_token`; or
- an actual `captcha-wrapper` element and `/help/pow-captcha` link after
  hydration (including the non-PoW failure screen).

Detection is status independent and bounded to 2 MB. Neither protocol words in
search results nor a plain 429/Retry-After is a Brave challenge. Ordinary 429s
retain the rate-limit path. Shared browser passthrough rejection recognizes the
same structural gate; it must never pass it through as search content.

Fixtures in `tests/fixtures/brave_{captcha_429,page1,page2}.html` are real
responses captured via wafer on 2026-10-25, copied from fetchaller's investigation.
They contain expired issued work, not live credentials. The original successful
captures do not prove a clean steady-state rate: the prior diagnostic had a
multiprocessing/import-side-effect issue. `tests/live_brave.py` is main guarded.

## Solving and limits

Install `wafer-py[browser]`, pass a `BrowserSolver`, and give the complete request
an adequate budget, for example:

```python
import wafer
from wafer.browser import BrowserSolver

with BrowserSolver(solve_timeout=120) as solver:
    with wafer.SyncSession(
        browser_solver=solver, max_rotations=0, max_retries=0,
        rate_limit=6, timeout=150,
    ) as session:
        response = session.get(
            "https://search.brave.com/search",
            params={"q": "Python asyncio documentation", "source": "web"},
        )
        # Check response.status_code and response.challenge_type.
```

AsyncSession uses the identical worker path. Without a browser, or after a
failed solve, `max_rotations=0` returns the original identified challenge;
otherwise `ChallengeDetected("brave")` is raised. Brave never rotates identities
or repeats a failed solve, regardless of the general retry/rotation settings.

The handler runs Brave's own JavaScript. Brave performs Argon2id work, prepares
the v2 POPRF (or its v1 fallback) batch request, submits `/api/captcha/pow`,
verifies/finalizes the batch proof, consumes a token, sets its real Secure cookie,
and reloads. Wafer does not invent cookies or implement partial cryptography.

Sets with ten or fewer tokens auto-start and are never clicked. For larger issued
sets, wafer clicks the enabled `.captcha-button-wrap button` once in `idle`.
`verifying` and `solved` are passive waits. Error/rejection, the non-PoW screen,
invalid main-frame navigation, and the caller's deadline stop the attempt. There
is no Try again loop, traditional slider solver, or fallback to generic JS wait.
A standalone `render()` reports this gate; the bounded solve path is `get()`.

Every first-party browser exchange uses the session's hostname limiter, including
initial navigation, key fetch, PoW submission, and reload. There are at most two
main-frame documents, one PoW submission, and two key requests (to allow Brave's
own v1 fallback). Pending first-party requests are bounded to 32 and released
by an independent task on the browser's asyncio loop. Release continues while
a synchronous DOM read, response-body read, or navigation is waiting; it does
not depend on the handler returning to its polling loop. Route callbacks never
sleep, so headless workers and iframe hardening keep running. Remaining routes
are aborted and handlers removed before context close. Required token-key, PoW,
and main-document requests have priority over optional feedback, keeping the
site's feedback bursts from consuming the recovery deadline. Every actual send
still respects the same limiter. Cleanup cancels pending pacing waits and lets
already-sent driver operations settle. CDN assets keep normal
browser scheduling. All work shares the
request deadline, response-size guard, and solver's configured proxy/egress.
A direct `solver.solve()` has its own timeout but no session limiter/state.

## Success, lifetime, and persistence

A PoW HTTP 200 is intermediate evidence. Success requires the completed real
HTML search **network response**, a 2xx status, the exact origin and route, all
original query parameters including query/page, and actual search-page markup.
No interstitial DOM or arbitrary quiet page is returned. Brave's traced `_rr=1`
reload parameter is tolerated only after an observed accepted PoW exchange;
other extra parameters or changed queries/pages are rejected.

If the browser navigation is challenge free while HTTP was challenged, its
validated network response is returned with `challenge_absent=True`, without
claiming a new clearance identity or changing the HTTP fingerprint. Recovery
requires an observed gate and the validated successful search network document.
This can follow accepted new PoW or reuse of an already-verified spare blind
token. Both are recovery (`challenge_absent=False`); this flag alone does not
prove a fresh PoW submission or portable cookie. A consumed cookie may already
be absent when the response is captured. Wafer allows up to three seconds,
inside the existing deadline, for the search app to prepare its next cookie;
it never substitutes a synthetic token when that handoff produces none.

Gate evidence includes earlier main-document **network response bodies** for
the exact original origin/query/page. A fast spare-token transition can finish
before the first DOM poll; the earlier structural gate still makes the final
response a recovery. Each retained response is inspected at most once for gate
evidence, within the existing response cap and deadline. An arbitrary earlier
429, a different query/host, or protocol prose does not establish a challenge.

Only validated success exports cookies to the HTTP jar and normal cookie cache.
Only the exact origin's `app.blindtoken.tokens[.v2]` keys survive into subsequent
solves, in **session-local memory**, never shared between sessions using the same
BrowserSolver. Context storage is seeded once at creation; an init script would
restore spent tokens on every reload and corrupt the pool. A failed attempt
retains no mutated browser state. Spare tokens are not written to disk; a new
session/process relies on ordinary persisted cookies and can solve again if
needed. Runtime cookie replay and restart acceptance must be measured separately
from browser success.

**Token cookies are consumable.** In the live run, one native HTTP search
carrying the real browser-issued token returned 200 and deleted that cookie.
The next gated search recovered using the retained spare-token pool, without
another PoW submission. Wafer lets Brave's own code consume the next token;
it does not keep replaying a spent cookie or synthesize token values. A fresh
process loaded an unspent cookie from disk and returned a 219,276-byte 200
search document with no browser configured; that read consumed the cookie too.
Restart persistence covers an unspent cookie, not an unlimited clearance grant.
The in-memory spare pool is intentionally not persisted. Once a restarted
session consumes its cached cookie, a subsequent gate can require new PoW.

## Verification record (2026-10-25)

### Accepted-reload stall

The original polling-only route queue could deadlock after accepted PoW. A live
native reproduction, without MCP or fetchaller's proxy, established the exact
blocked sub-call: CDP `Runtime.evaluate` inside `_quiet_read`, before
`page.content()` was called. Chrome was navigating to the accepted exact-query
`_rr=1` reload, whose route was waiting for the six-second limiter. Only the
outer handler loop could release that route, and that loop was blocked in the
read. The 234.9-second browser deadline interrupted the driver; extending the
deadline did not fix the circular wait.

Route release now runs independently on the driver's event loop, including
during pending sync protocol calls. The bridge uses the intercepted route's
underlying asynchronous implementation on its owning loop. The real-driver
probe `tests/live_brave_pacing.py` deliberately awaits concurrent token-key
fetches inside `evaluate()` and a paced `reload()` without an outer polling
loop. Unit regressions also cover pacing, cancellation, deadline, rejection,
and route failure. Debug logs report route paths/queue lengths and DOM-read
entry/exit without issued work or cookie values.

The stronger real-driver probe also exposed bursts of `/api/feedback` requests
queued before the final document. A FIFO for every first-party request could
delay the reload past its budget even after the read deadlock was removed.
Required exchanges now retain FIFO ordering ahead of optional feedback; no
telemetry exception bypasses the session's limiter.

### Recovery verified after the fix

These live runs used installed macOS Chrome 155, headed and headless.

- Final wafer suite: **2,845 passed, 25 skipped**, including **64 Brave cases**;
  Ruff, lockfile validation, and diff checks passed. Fetchaller's full suite
  against the local fix: **4,603 passed, 5 skipped**, with five dependency
  deprecation warnings. Source distribution and wheel built successfully.
- Native headed run: HTTP 429 and a real browser gate, PoW 200 at 23:25:41 UTC,
  completed exact-query `_rr=1` search 200 at 23:25:53, **215,688 network bytes**,
  returned to the caller in **30.68 seconds**. No MCP or fetchaller proxy was
  involved.
- Native headless run: fresh PoW 200 at 23:33:00 UTC, completed `_rr=1` search
  200 at 23:33:12, **227,317 network bytes**, returned in **30.97 seconds**.
  Two later native HTTP reads returned search content and consumed their token
  cookies. Two later gated queries/pages recovered from spare blind tokens in
  **12.58 / 12.69 seconds**, with **no additional PoW submissions**.
- A restarted session with **no BrowserSolver configured** loaded an unspent
  cookie from disk and returned a **219,276-byte HTTP 200** search document.
  An independent fresh Python process also loaded an unspent cookie and
  returned the same size successful document without a browser. Both reads
  consumed their token cookies; repeated reuse is not the protocol.
- The headless run also established the response/cookie timing race: final
  network content could arrive before the new search app prepared its next
  cookie. Recovery no longer depends on the consumed cookie remaining present,
  and bounded app settling retains a newly prepared cookie when available.
  Final origin/query, rejection, size, and deadline checks run again after
  this handoff, before state export.
- The actual guarded fetchaller **stdio MCP** path recovered a fresh gate and
  returned **20 attributed Brave results in 31.13 seconds**. Solver audit:
  `response_status=200 challenge_absent=False`; one browser dispatch;
  **27 egress connections allowed, zero denied**. It used local wafer source,
  fetchaller's existing guarded shared solver, and its normal request/provider
  budgets. No fetchaller implementation change was needed for this fix.
- The real headless pacing probe completed an awaited two-fetch `evaluate()`
  and a paced `reload()` without any outer flush loop. Search/reload were real
  429 gates, and both public key responses were 200. Send gaps were **6.139,
  6.365, and 6.281 seconds**, with no cleanup errors. This verifies independent
  route progress/pacing; it is not counted as a PoW solve.

Reproduce the complete native acceptance flow:

```bash
uv run python tests/live_brave.py --rounds 10 --require-recovery
uv run python tests/live_brave.py --headless --rounds 10 --require-recovery
```

The probe requires fresh accepted work and validated recovered content, native
token replay, subsequent spare-token recovery without new PoW, and an unspent
cached token accepted after session restart. No-gate or missing-evidence runs
exit 2; an unresolved response stops live traffic and exits 1. Token/cookie
values are never logged. Local evidence: `/tmp/wafer-brave-subcalls-before.out`,
`/tmp/wafer-brave-fixed-recovery.out`, and
`/tmp/wafer-brave-fixed-headless-final.out`. Guarded integration and pacing:
`/tmp/fetchaller-wafer-brave-fixed-mcp.out` and
`/tmp/wafer-brave-pacing-pass.out`.

### Fast spare-token classification follow-up

Independent verification of `8e9844b` found a remaining metadata race: a
429-to-200 spare-token transition could finish before the first DOM poll,
returning correct search content with `challenge_absent=True`. That also skipped
the recovery-specific HTTP identity alignment and next-cookie wait. The earlier
live pass did not cover every timing of this transition.

The handler now inspects retained exact-target main-document response bodies
before declaring the latest successful response challenge-free. This preserves
structural gate evidence across a completed navigation without relying on new
PoW, a surviving DOM, or cookie presence. Regression coverage supplies the real
gate and final document before any DOM poll, including through BrowserSolver's
normal response listeners; plain 429, wrong-host/page, non-HTML, prose, and
response-size controls remain enforced. The native acceptance probe is unchanged.

The new headless run accepted fresh PoW and returned **225,115 bytes in 31.31s**.
Both later spare recoveries were correctly classified (`cleared=True`,
`pow_accepted=False`, `challenge_absent=False`) in **12.83 / 12.77 seconds**,
with no new PoW. Native HTTP reads consumed their real token cookies, and the
browser-free cache restart returned **216,788 bytes, HTTP 200**. Log:
`/tmp/wafer-brave-history-headless.out`. The original failing independent run
is `/tmp/wafer-brave-8e9844b-native.out`.

The headed probe also passed, with both spare recoveries correctly classified
in **12.71 / 12.68 seconds** and a browser-free **216,788-byte HTTP 200** cache
restart. Every spare recovery in both new runs was `challenge_absent=False`;
the probes were not satisfied by just one correctly labelled transition.
Headed log: `/tmp/wafer-brave-history-headed.out`. Final suite: **2,856 passed,
25 skipped**, including **75 Brave cases**; Ruff, lockfile and diff checks
passed.

### Earlier verification

The following records the earlier implementation before the stall and
cookie-handoff fixes. Its limitations are superseded by the live record above.

- Final lint passed; full suite: **2,832 passed, 25 skipped**, including
  **51 Brave regression cases**. Offline coverage includes the real capture, successful page 1/2,
  malformed/large/prose/lookalike controls, no-browser sync/async behavior,
  no-rotation browser failure, manual/automatic start, rejection, deadline,
  detached context, exact network/query validation, and session-local state.
- Guarded live run: page 1 was 200; page 2 was a detected 429. Brave's own PoW
  endpoint returned 200 and its subsequent search document was 200. The first
  implementation rejected that reload's `_rr=1` and timed out honestly instead
  of returning a gate. The reload validator was corrected and has regression
  coverage.
- Three subsequent guarded runs completed multiple queries, pagination, and a
  session restart with HTTP 200 throughout, but triggered no PoW. They verify
  ordinary searches only. At that stage, end-to-end acceptance of the corrected
  PoW capture, cookie replay, and clearance persistence were **unverified**.
- A real headless Chrome search and two concurrent public token-key requests
  returned 200/200/200. The actual send intervals were 6.325 and 6.473 seconds.
  Pending routes were cleaned up without callback/cancellation errors. Reproduce
  with `uv run python tests/live_brave_pacing.py`; this tests browser pacing,
  not PoW acceptance.
- Direct `BrowserSolver.solve(..., "brave")` returned HTTP 200 and 213,542
  network bytes with `challenge_absent=True`, verifying the challenge-free
  browser path end to end.
- A bounded intentional trigger probe stopped after four successful HTTP
  searches without a gate. This is not a solve proof.
- The real wreq jar and disk cache preserve Brave's actual cookie name,
  Secure/path/domain scope and lifetime in an offline round trip. This uses a
  test token and does not prove the server will accept a replayed live token.
- Session-level validation also rejects an interstitial or changed query/page
  from a custom browser solver before importing cookies or caching state.

## Early triggering investigation

The detector/Verify gaps are confirmed. A fingerprint cause of the early gate is
not established. On this machine normal installed Chrome is 155.0.8059.85, whereas
wreq's newest profile is Chrome 154.0.8037.93. The existing browser identity warning
reports that difference. This observation alone does not establish causation and
is not a reason to rotate profiles. A headed Chrome CDP capture on the actual
Brave route showed a document navigation (`none`, `navigate`, `?1`), Chrome 155
hints/UA, HTTP/2, and no Brave cookies. Wafer's request also returned 200 without
Brave cookies; its configured envelope uses Chrome 154. Chrome 155 additionally
advertised `image/jxl`. These version-specific differences do not establish a
fingerprint defect. Attempts to collect comparable TLS echo measurements at
`tls.peet.ws` ended in connection/request deadlines for both clients, so no new
TLS wire equivalence is claimed. The early-trigger cause remains unresolved.

Fetchaller owns only orchestration and result parsing. Its existing guarded
BrowserSolver must be passed to the Brave session with a sufficient request and
provider deadline. Keep its six-second provider gate and `max_retries=0`,
`max_rotations=0`. Google Docs research-search must remain browser free.
