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
from the browser event pump; route callbacks never sleep, so headless workers
and iframe hardening keep running. Remaining routes are aborted and handlers
removed before context close. CDN assets keep normal browser scheduling. All work shares the
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
claiming a new clearance identity or changing the HTTP fingerprint. Fresh
clearance additionally requires an observed accepted PoW exchange and the real
Brave cookie on the successful document.

Only validated success exports cookies to the HTTP jar and normal cookie cache.
Only the exact origin's `app.blindtoken.tokens[.v2]` keys survive into subsequent
solves, in **session-local memory**, never shared between sessions using the same
BrowserSolver. Context storage is seeded once at creation; an init script would
restore spent tokens on every reload and corrupt the pool. A failed attempt
retains no mutated browser state. Spare tokens are not written to disk; a new
session/process relies on ordinary persisted cookies and can solve again if
needed. Runtime cookie replay and restart acceptance must be measured separately
from browser success.

## Verification record (2026-10-25)

Run the guarded end-to-end probe with `uv run python tests/live_brave.py`.
It stops at the first unresolved response and labels challenge-free runs
untested for PoW solving.

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
  ordinary searches only. End-to-end acceptance of the corrected PoW capture,
  cookie replay, and clearance persistence remain **unverified** until another
  real gate triggers. Do not describe those as passed based on those clean runs.
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
