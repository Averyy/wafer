# Brave Search proof of work: handoff and implementation status

Requested by Avery on 2026-10-25. Original handoff is preserved below.

**Implementation status:** dedicated `brave` detection and a bounded browser
handler now exist in wafer. They include one-shot Verify, session pacing and
state isolation, exact network-response capture, and the accepted `_rr=1`
reload. See [the current solver reference](docs/ref-brave.md) for support limits
and the verification record. Live PoW acceptance and a subsequent 200 search
were observed; the initial validator rejected that reload and was corrected.
Later live runs were challenge free, so corrected challenged capture and real
HTTP clearance replay/persistence remain unverified. Intended release: 0.7.9;
not released by this work. Fetchaller integration is unchanged.

No wafer code changes from the original fetchaller investigation remained when
this implementation began.

## Original problem and confirmed evidence

Fetchaller's Brave provider can return 20 organic results on page 1, then receive
HTTP 429 on page 2 even with six-second minimum spacing. The captured response
is a first-party Brave proof-of-work interstitial, not evidence of a published
quota being exceeded. Do not assume an IP ban or fix this by rotating profiles.

Repro against the installed wafer-py 0.7.7 (same detector behavior in this local
checkout): `detect_challenge(429, {"content-type": "text/html"}, body,
url="https://search.brave.com/search?q=Python+asyncio+documentation&source=web&offset=1")`
returns **None** for the real 73,896-character body. There is no dedicated Brave
detector. The generic-JS fallback only considers bodies below 50,000 characters.
Therefore the page is treated as an ordinary 429: attaching BrowserSolver alone
does not dispatch a solve. Raising the generic size limit is not a sufficient fix.

Real response fixtures, readable from this machine:

- `/Users/avery/Code/fetchaller-mcp/tests/fixtures/brave_captcha_429.html`
- `/Users/avery/Code/fetchaller-mcp/tests/fixtures/brave_page1.html`
- `/Users/avery/Code/fetchaller-mcp/tests/fixtures/brave_page2.html`
- Provenance/caveat: `tests/fixtures/brave_search.md` in that repo.

The captured blocked page has internal Svelte `page:"/captcha"` while the
requested URL remains `/search?...`. Its issued script data contains
`challengeSet:{set_token:...,tokens:[...],zero_count:1,
hash_function_params:{iterations:2,memory_size:512,hash_length:32,parallelism:1},
solution_limit:5000}`. This capture has **100 tokens**.

## Protocol traced from Brave's own current JS

These were fetched through wafer, sequentially, on 2026-10-25. Saved source in
`/tmp/brave-protocol/` is diagnostic evidence; hashed asset URLs may change.

- `https://cdn.search.brave.com/serp/v3/_app/immutable/entry/app.jTQS8Lii.js`
  maps Svelte node 11 to `../nodes/11.B8NIASEa.js`.
- `nodes/11.B8NIASEa.js` (`/tmp/brave-protocol/captcha.js`) renders
  `.captcha-wrapper[data-state]`: `idle`, `verifying`, `solved`, `error`.
  Sets with <=10 tokens auto-start. **Larger sets need the Verify button** in
  `.captcha-button-wrap button`. Generic "wait for JS" does not initiate these.
- `chunks/olBSYVT_2.js` carries the worker: for each issued token, generate a
  random 16-byte salt encoded as 32 lowercase hex characters; Argon2id uses the
  token string as password and the **ASCII hex salt string**, not decoded salt
  bytes. Find a digest starting with `zero_count` hex zeroes within
  `solution_limit`. Collect `{issued_token: salt_string}` plus milliseconds
  `taken_time`. The example parameters above are data, not constants to pin.
- `chunks/DtJORqhT.js` manages blind tokens. Fetch `/api/tokens/keys`, prepare a
  batch request, and validate/finalize the server's batch proof. Current client
  prefers v2 POPRF (`blinded_elements`, `key_id`, `ts`, `scheme:"v2"`), with v1
  (`blinded_messages`, `key_id`) as its own fallback. It is **not just hash then
  set a made-up cookie**. The client stores spare tokens in localStorage under
  `app.blindtoken.tokens[.v2]`; keys response supplies tokens_per_challenge
  (client fallback 30).
- `chunks/DnqrizKG2.js` posts JSON to `/api/captcha/pow?brave=0` for ordinary
  Chrome: `{set_token,solutions,taken_time,...blind_request}`. On HTTP 200 it
  finalizes/validates the batch, consumes one token, sets
  `__Secure-token#brave-search-captcha-v2` (or v1 name without `-v2`) with
  Secure, Path=/, SameSite=Strict, Max-Age=172800, and reloads the search.
  Do not include real issued token/cookie values in logs.

## Requested wafer work

1. Add scoped structural detection of this actual first-party challenge,
   including its hydrated browser document. Avoid matching ordinary Brave
   results containing words like CAPTCHA, `challengeSet`, or "access denied".
   Ordinary 429/Retry-After responses must keep their existing rate-limit path.
2. Add a bounded solve path. A browser handler can run the site's own Argon2 and
   blind-token code and press **Verify once**, without implementing the
   cryptographic protocol in the caller. Small sets may already be running;
   never restart them. Stop on `error`, timeout, rejection, or the separate
   traditional slider; no repeated "Try again" loops or profile rotation.
   A native solver is also viable only if it implements and verifies the full
   protocol with bounded untrusted work, not just the Argon2 loop.
3. Return the **real completed search network response**, not the interstitial
   DOM or a generic quiet page. Validate final status, origin/route, body and
   original query/page. BrowserSolver's shared passthrough validator currently
   does not recognize this challenge either; it must never return the gate as
   successful content. A browser navigation may also be challenge-free while
   HTTP was challenged; safely return that exact network response without
   claiming a clearance token was earned.
4. Check lifetime/reuse. `_solve_on_worker` creates/closes a fresh browser
   context for each solve, so spare blind tokens in localStorage would be lost.
   Decide how to retain origin-scoped anonymous state safely and verify whether
   the consumed cookie transfers to wreq and supports later searches. Do not
   infer replay works just because the browser solved once. Cache only validated
   successful clearance; never persist rejected state as usable clearance.
5. Preserve session limiter and end-to-end deadline on all extra network
   exchanges/replays. Fetchaller uses `max_rotations=0,max_retries=0,rate_limit=6`;
   a bounded challenge solve must work with those settings, without turning
   general retries back on or bursting search calls inside the solver.
6. Compare the actual HTTP and normal Chrome requests (headers/TLS/navigation/
   cookies) to investigate why the gate triggers after so few requests. The
   unrecognized challenge is confirmed; a fingerprint defect or IP cause has
   **not** been established. Report trigger prevention separately from solving.

## Acceptance / regression tests needed

- Real captured 429 classified correctly; successful page 1/page 2 and ordinary
  429 without issued challenge data are negative controls. Include a large or
  malformed page, lookalike host and docs/prose mentioning the protocol.
- No browser: returns/raises an explicit identified challenge using existing
  bulk/max_rotations=0 semantics; no fake empty result, rotation or retry storm.
- Browser: auto-started small set, manual-start large set, rejection, timeout,
  detached context during redirect, and challenge-free browser navigation.
  Keep response-size, egress, redirect, query/page and deadline guarantees.
- Guarded real live run through **wafer itself**: one session, >=6 seconds
  between searches; reproduce the challenge and observe accepted work/token
  response plus actual search content. Then verify multiple queries and pages
  on that same session and a restart/persistence case. Stop on unresolved block.
  If no challenge triggers, mark solving untested, not passed. No process-import
  side effects: live diagnostic scripts must use `if __name__ == "__main__"`.
- Update llms.txt and solver docs with the actual challenge type, settings,
  support limits and verified runtime behavior; provide a release version.

## Fetchaller integration / current protection

Fetchaller owns orchestration and results only. Its shared per-provider gate
serializes the complete HTTP exchange with >=6 seconds plus jitter between
requests, across explicit Brave, `all`, and Google fallback. Wafer sessions
disable hidden retry/rotation and use wafer's six-second limiter as well.
Unresolved 429/403 gets 60s/300s cooldown, extended by longer Retry-After.

The current search session does not receive the server's existing guarded
BrowserSolver, and its 10s request/15s provider deadlines would be too short
for reliable challenge handling. Fetchaller can connect that solver and budget
once the wafer handler exists. **Google must remain browser-free on the Google
Docs research-search endpoint.** No CAPTCHA detection/solving, cookie injection,
blind-token implementation, custom fingerprint or identity rotation should be
added to fetchaller. Keep direct/`all`/fallback pacing and honest errors.

See `/Users/avery/Code/fetchaller-mcp/docs/brave-search-investigation.md` for the
prior guarded stdio MCP run and pacing fixes. Earlier unguarded diagnostics
duplicated requests in parser worker processes; those runs do not prove a
clean steady-state traffic rate. Do not use them to claim an IP ban or that
six-second spacing is universally sufficient to avoid this challenge.
