# TODO: Replace the Old Reddit session bootstrap

Status: wafer phase W1 implemented and validated on 2026-07-26. Release and the
fetchaller dependency update in phase W2 remain pending.

Related fetchaller plan:
[`../fetchaller-mcp/todo-newreddit.md`](../fetchaller-mcp/todo-newreddit.md)

## Objective

Replace wafer's `https://old.reddit.com/` anonymous-cookie warmup with New
Reddit's logged-out verification flow.

After this change, a cold request such as:

```text
https://www.reddit.com/r/python/hot.json?limit=1
```

must succeed without:

- a Reddit account;
- OAuth or a borrowed first-party client ID;
- a browser process;
- any automatic request or fallback to `old.reddit.com`;
- downloading the large post-verification New Reddit homepage.

Wafer remains responsible for transport, challenge handling, cookies, retry,
deadlines, and persistence. It must not parse or render Reddit content; that
belongs in fetchaller.

## Decision

Use New Reddit's own logged-out JavaScript verification as wafer's inline
`ChallengeType.REDDIT` solver:

```text
cold anonymous JSON request
  -> Reddit 403 network-security gate
  -> GET https://www.reddit.com/
  -> parse the small verification form/script
  -> submit its solved same-origin GET in the same wreq session
  -> persist the anonymous cookies from response headers
  -> discard the normal homepage response without reading its body
  -> replay the original JSON request once
```

Do not use Redlib-style Android OAuth impersonation. Do not move this solver
into fetchaller.

### Old Reddit support boundary

Wafer still supports an explicit `old.reddit.com` URL as an ordinary request:
TLS fingerprinting, cookies, retries, and challenge detection continue to
apply. It must not rewrite that request. If Reddit returns a login wall, wafer
returns it normally and does not try to bypass the account requirement.

Old Reddit is not a bootstrap strategy. Cold Reddit JSON sessions verify only
through `www.reddit.com`; wafer never selects Old Reddit automatically or uses
it as a fallback. Fetchaller-generated traffic must likewise never select Old
Reddit.

## Ownership boundary

### Wafer owns

- Detecting the existing Reddit cold-session JSON gate.
- Strict validation of Reddit hosts and verification form destinations.
- Parsing and solving the recognized logged-out verification challenge.
- Reusing the exact wreq client/fingerprint that received the challenge.
- Caching cookies from every bootstrap response leg.
- Persisting solver cookies when `cache_dir` is configured.
- Bounding solver subrequests by the original request deadline.
- Avoiding duplicate bootstrap work in a shared `AsyncSession`.
- Retrying the original request exactly once after a successful bootstrap.
- Returning the existing wafer errors when verification cannot be solved.

### Fetchaller owns

- Mapping normal Reddit URLs to anonymous JSON endpoints.
- Selecting and rendering Reddit fields.
- Token-budget-aware post/comment output.
- Reddit-specific 403/404 content-state messages.
- Reddit request queueing and application-level response caching.

Wafer must not learn about Reddit posts, comments, galleries, polls, profiles,
rules, or wikis.

## Verified live behavior

A fresh `wafer.SyncSession` with an empty temporary cookie cache was tested
against the real site.

### Verification response

`GET https://www.reddit.com/` returned:

- status 200;
- an 8,424-character verification page;
- title `Reddit - Please wait for verification`;
- a same-origin hidden GET form;
- hidden fields:
  - `solution`;
  - `js_challenge=1`;
  - `token`;
  - `jsc_orig_r`;
- a small inline script that derived the solution from a server-provided seed.

The observed script doubled the seed. The implementation must recognize the
served calculation structurally and fail closed if it changes. It must not
hard-code the observed seed, token, or final solution.

### Solved response

Submitting the form through the same internal wreq client returned:

- status 200;
- a normal New Reddit homepage;
- approximately 513-536 KB of body data if consumed;
- `Set-Cookie` headers for:
  - `loid`;
  - `session_tracker`;
  - `csrf_token`;
  - `token_v2`;
  - `csv`.

After those cookies were installed, the original anonymous JSON request
returned 200.

### Cookie persistence

The persistent cookies were written through wafer's existing `CookieCache`.
A completely new `wafer.SyncSession` using the same cache directory then
fetched Reddit JSON successfully without another verification request.

### Body consumption

wreq installs response cookies and exposes response headers before the response
body is consumed. The solved homepage body is unnecessary:

1. validate the response status;
2. inspect and persist `Set-Cookie`;
3. validate expected cookie names;
4. drop the raw response;
5. replay the JSON request.

The verification page itself is small and must be read under a dedicated
solver cap. The normal homepage must not be read.

## Previous implementation and failure mode

Before this change, the implementation was distributed across:

- `wafer/_solvers.py`
  - `reddit_warmup_url()` validates the host and returns
    `https://old.reddit.com/`.
- `wafer/_sync.py`
  - `_try_inline_solve()` fetches Old Reddit and accepts any 2xx as success.
- `wafer/_async.py`
  - contains the equivalent async behavior.
- `tests/test_solvers.py`
  - asserts that Reddit hosts use Old Reddit and models a three-request
    gate/warmup/replay flow.
- `docs/site-list.md`
  - documents Old Reddit as the intentional warmup.
- `llms.txt`
  - tells users that the inline Reddit solver fetches Old Reddit.

That design fails once logged-out Old Reddit is login-gated:

1. the Old Reddit warmup can still return a 2xx login response;
2. wafer currently treats that as a successful solve;
3. the required anonymous cookie evidence may be absent;
4. the replayed JSON request remains blocked;
5. cold Reddit access becomes unreliable.

## Proposed implementation

### 1. Replace the URL-only helper with strict verification helpers

In `wafer/_solvers.py`:

- retain strict Reddit hostname validation:

  ```python
  host == "reddit.com" or host.endswith(".reddit.com")
  ```

- normalize a trailing DNS dot before comparing;
- return only the fixed solve origin `https://www.reddit.com/`;
- reject hostile lookalikes such as:
  - `notreddit.com`;
  - `reddit.com.evil.test`;
  - Reddit text appearing only in a query string;
- add a small, pure parser for the verification document.

The parser should return either a typed internal solve description or `None`.
It must not execute arbitrary JavaScript.

Validate:

- expected verification markers/title;
- a GET form;
- a same-origin `/` action;
- all required hidden fields;
- `js_challenge` having the expected value;
- exactly one recognized solution calculation;
- a bounded seed with the expected character class;
- no unexpected cross-origin URL.

Use `html.unescape()` for form values and `urllib.parse.urlencode()` to build the
query. Do not log or expose the resulting query.

### 2. Bound the verification-page read

Add an internal constant such as:

```text
REDDIT_VERIFICATION_MAX_BYTES = 32 KiB
```

The exact value should leave reasonable headroom above the observed 8,424-byte
page while remaining far below the 500+ KB normal homepage.

In the sync path, use wafer's existing `_read_body_capped()`. In the async path,
use `_aread_body_capped()`. A cap breach means the inline solve is not
recognized and must fail closed.

Do not call `.text()`, `.bytes()`, or `.stream()` on the solved normal homepage
response.

The solver cap is internal challenge overhead. It should not weaken or replace
the caller's `max_response_size` limit for the final response.

### 3. Implement the sync bootstrap

Replace the `ChallengeType.REDDIT` branch in
`SyncSession._try_inline_solve()`:

1. Validate the challenged URL as Reddit.
2. Recompute the remaining request deadline.
3. GET `https://www.reddit.com/` with the current internal wreq client.
4. Cache any `Set-Cookie` headers immediately.
5. If the response already establishes sufficient anonymous cookie evidence,
   return success without reading its body.
6. Otherwise, read the verification body under the dedicated cap.
7. Parse the verification challenge.
8. Recompute the remaining deadline again.
9. Submit the solved same-origin GET using the same client.
10. Require a 2xx response.
11. Cache all solved-response `Set-Cookie` headers before any body access.
12. Require `loid` plus at least one other expected durable/session marker such
    as `token_v2` or `csv`.
13. Drop the solved response without consuming the body.
14. Return success so the existing retry loop replays the original request.

The original 403 response cookie leg must continue to be cached before solving.

Do not reuse one initially calculated timeout for both network legs. Each leg
must be clamped to the current remaining deadline so their combined duration
cannot exceed the caller's overall timeout.

### 4. Implement exact async parity

Apply the same behavior in `AsyncSession._try_inline_solve()` using async wreq
calls, `_aread_body_capped()`, and `asyncio.to_thread()` for disk-cache writes.

Because `AsyncSession` is designed to be shared across concurrent coroutines,
add a dedicated per-session Reddit-bootstrap lock:

1. acquire the lock after a request detects the Reddit gate;
2. compare a successful-bootstrap generation after acquiring it;
3. if another coroutine already solved on the still-current client generation,
   skip the verification network calls and replay;
4. otherwise perform one bootstrap;
5. release the lock before replaying the caller's original request.

Do not use a module-global lock. Independent sessions must remain independent.
Do not broaden `SyncSession` thread-safety; it remains explicitly not
thread-safe.

### 5. Preserve existing retry semantics

Keep Reddit's special retry behavior:

- one inline bootstrap attempt per original request;
- no fingerprint rotation budget consumed by a successful inline solve;
- one replay after successful verification;
- no repeated verification loop when the replay is still blocked;
- normal failure/rotation/error behavior when parsing or cookie validation
  fails;
- `inline_solves == 1` on a successful bootstrap;
- no browser solver requirement.

Rename internal variables such as `reddit_warmup_attempted` to
`reddit_bootstrap_attempted` where it improves clarity.

### 6. Validate cookies without exposing values

Cookie success checks must compare names only. Never log:

- hidden form tokens;
- the seed or solution;
- query parameters;
- `loid`;
- `token_v2`;
- `csrf_token`;
- cookie values.

Logs may identify only the safe stage:

- verification page fetched;
- verification submitted;
- anonymous cookies established;
- bootstrap failed due to structure/status/cookie evidence.

Do not include the solved query URL in logs, exceptions, or request history
returned to callers.

## File-by-file plan

### `wafer/_solvers.py`

- Replace `reddit_warmup_url()` with strict solve-origin and parser helpers.
- Add verification constants and an internal typed result.
- Keep parsing pure and independently unit-testable.
- Update the module docstring to include Reddit verification.

### `wafer/_sync.py`

- Import the new Reddit helpers.
- Use a bounded read for the small challenge document.
- Implement the two-leg New Reddit verification flow.
- Persist cookies before dropping the solved response.
- Recompute remaining deadline per leg.
- Remove all Old Reddit requests and log messages.

### `wafer/_async.py`

- Mirror sync behavior exactly.
- Add and initialize the per-session Reddit-bootstrap lock.
- Re-check cookie state after acquiring the lock.
- Keep disk writes off the event loop.

### `tests/conftest.py`

- Extend the cookie-jar mock only as needed to represent cookie-name reads.
- Add response types whose body access raises, allowing tests to prove that the
  solved homepage is never consumed.
- Preserve existing test behavior for unrelated solvers.

### `tests/test_solvers.py`

- Keep unrelated inline-solver coverage and add the Amazon GET-form regression
  assertion discovered while validating raw wreq argument handling.

### `tests/test_reddit.py`

- Replace Old Reddit URL assertions and three-response fixtures.
- Add parser, sync, async, cookie, cap, timeout, concurrency, client-generation,
  cancellation, and one-attempt coverage.

### `tests/test_attempt_timeout.py`

- Add or extend deadline tests so both verification legs share the caller's
  original deadline.

### `docs/ref-reddit.md`

Add a focused internal solver reference covering:

- detection signal;
- New Reddit verification sequence;
- cookie evidence;
- retry semantics;
- body-consumption rule;
- live-test procedure;
- known failure modes.

### `docs/site-list.md`

Replace the July 18 Old Reddit entry with the verified New Reddit flow and the
new validation date.

### `llms.txt`

Replace the statement that wafer fetches `old.reddit.com`. The public behavior
remains automatic and browser-free; document that wafer now performs New
Reddit's logged-out inline verification and persists the resulting cookie legs.

No new public session parameter or API is expected.

### `README.md`

Replace the Old Reddit warmup description and document the explicit-request
support boundary.

## Test plan

### Parser unit tests

- Valid observed verification document.
- Hidden fields in a different safe order.
- HTML-escaped form values.
- Missing form.
- Wrong form method.
- Cross-origin form action.
- Missing or duplicate required fields.
- Wrong `js_challenge` value.
- Missing seed.
- Invalid/oversized seed.
- Missing calculation.
- Changed or unrecognized calculation.
- Multiple ambiguous calculations.
- Normal New Reddit HTML is not misidentified as the verification challenge.

### Sync integration tests

Model the complete request sequence:

1. JSON returns the Reddit 403 gate and first cookie leg.
2. `www.reddit.com/` returns the small verification document.
3. The solved same-origin GET returns expected `Set-Cookie` headers.
4. The response body raises if accessed.
5. Replayed JSON returns 200.

Assert:

- exact request ordering;
- no automatic or fallback `old.reddit.com` request;
- solved query contains all required fields without asserting/logging secrets;
- solved homepage body was not read;
- all response cookie legs were persisted;
- replay succeeds with no rotation;
- `inline_solves == 1`.

Also cover:

- verification origin already returns sufficient cookies;
- first or second leg non-2xx;
- malformed verification;
- missing required cookie evidence;
- verification body over the internal cap;
- timeout before each leg;
- replay still blocked;
- bootstrap attempted at most once.

### Async integration tests

Mirror every sync success/failure invariant and add:

- two concurrent cold Reddit requests share one bootstrap;
- a waiting coroutine skips solving after cookies appear;
- a failed first bootstrap releases the lock;
- cancellation releases the lock;
- disk cookie writes use the async-safe path.

### Persistence test

Using `CookieCache` and a temporary directory:

1. complete the mocked New Reddit solve;
2. assert all expected cookie names were persisted;
3. create a fresh session with the same cache;
4. assert its jar hydrates with the Reddit domain cookies.

### Live smoke test

Follow `CLAUDE.md`: test wafer with wafer itself, never through fetchaller.
Pace requests by at least five seconds and use a temporary cache.

1. Start with an empty cache and `max_rotations=0`.
2. Request a one-item `www.reddit.com` JSON listing.
3. Observe the real Reddit challenge and successful replay.
4. Assert JSON 200 and `inline_solves == 1`.
5. Confirm logs/request instrumentation contain `www.reddit.com` and no
   `old.reddit.com`.
6. Recreate the session with the same cache.
7. Wait at least five seconds.
8. Repeat the JSON request.
9. Assert JSON 200 with no second verification.
10. Run an async smoke test with the same invariants.

If the real challenge does not trigger, record the cold-solve portion as
untestable rather than passed. A warm-cache success alone does not validate the
solver.

### Required repository checks

Before any wafer commit:

```bash
uv run ruff check wafer/ tests/
uv run pytest tests/ -x -q
```

Also run the focused tests during development:

```bash
uv run pytest tests/test_solvers.py tests/test_attempt_timeout.py -x -q
```

## Cross-repository sequencing

### Phase W1: implement wafer

- Add the parser and sync path.
- Add async parity and cold-start deduplication.
- Replace all Old Reddit tests.
- Update `docs/ref-reddit.md`, `docs/site-list.md`, and `llms.txt`.
- Run focused and full wafer checks.
- Run cold-cache and warm-cache live tests.

Exit gate: wafer can anonymously fetch Reddit JSON from a new cache without any
Old Reddit request.

### Phase W2: make wafer consumable by fetchaller

- Commit/release wafer using the repository's normal version/tag workflow.
- Update fetchaller's wafer dependency/lockfile to the exact tested revision or
  release.
- Do not retain a hidden Old Reddit fallback in wafer.

Exit gate: fetchaller's environment imports the New Reddit-capable wafer build.

### Phase F: implement fetchaller

The sibling plan owns this phase. In summary:

- stop rewriting normal URLs to Old Reddit;
- add Reddit JSON URL routing and compact renderers;
- preserve the verified public read feature matrix;
- enforce token budgets at content boundaries;
- run local MCP integration tests on the upgraded wafer.

Wafer work is complete before fetchaller removes its Old Reddit URL transform.
This prevents a cold-session window where fetchaller requests JSON but wafer
still depends on the Old Reddit warmup.

## Acceptance criteria

- No automatic wafer path requests `old.reddit.com`; explicit requests remain
  supported and unchanged.
- A cold anonymous sync session obtains Reddit JSON through New Reddit
  verification.
- A cold anonymous async session has the same behavior.
- Concurrent async cold requests perform at most one verification bootstrap.
- The verification document is read under a small fixed cap.
- The solved 500+ KB homepage body is never consumed.
- Required anonymous cookie names are validated and persisted.
- A new process/session reuses cached cookies without re-verifying.
- The original request deadline bounds both verification network legs and the
  replay.
- A changed challenge structure fails closed.
- Reddit solving remains inline and browser-free.
- Retry/rotation accounting remains compatible with current behavior.
- No secrets or pseudonymous cookie values appear in logs or caller-visible
  history.
- Sync and async tests, full pytest, ruff, and real cold/warm smoke tests pass.
- `docs/ref-reddit.md`, `docs/site-list.md`, and `llms.txt` describe the new
  behavior.

## Risks

1. Reddit can change the verification script. Keep the parser narrow, tested,
   and easy to update; never execute arbitrary served JavaScript.
2. Anonymous JSON can be withdrawn independently of logged-out HTML. That is a
   service capability risk, not a reason to impersonate Android OAuth.
3. Cookie names or combinations can change. Validate enough evidence to reject
   a 2xx login/interstitial while avoiding an unnecessarily brittle exact set.
4. A shared `AsyncSession` can see simultaneous cold failures. The dedicated
   lock and post-lock cookie re-check are required to avoid redundant solves.
5. Accidentally reading the solved homepage would add roughly half a megabyte
   per cold session. The non-consumption tests are release-blocking.

## Completion checklist

- [x] Parser helpers implemented.
- [x] Sync verification implemented.
- [x] Async verification and lock implemented.
- [x] No automatic or fallback Old Reddit code path remains.
- [x] Explicit Old Reddit requests remain unchanged.
- [x] Parser and integration tests pass.
- [x] Deadline and response-body tests pass.
- [x] Cookie persistence across session recreation passes.
- [x] Cold and warm live sync tests pass.
- [x] Cold and warm live async tests pass.
- [x] Explicit Old Reddit live request remains on the requested host.
- [x] `README.md` updated.
- [x] `docs/ref-reddit.md` added.
- [x] `docs/site-list.md` updated.
- [x] `llms.txt` updated.
- [x] Ruff passes.
- [x] Full pytest passes (1,195 passed, 6 skipped).
- [ ] Fetchaller dependency is updated to the tested wafer version.
