# Reddit anonymous-session bootstrap

Wafer handles Reddit as one transport-level challenge, without understanding
posts, comments, or other Reddit content.

## Supported behavior

| Request | Wafer behavior |
|---|---|
| Explicit `old.reddit.com` URL | Fetch the URL as requested. Return a login wall normally if Reddit requires an account. |
| Cold Reddit JSON session | Bootstrap only through `https://www.reddit.com/`, then replay the original URL. If the exact inline flow fails and `browser_solver` is configured, recover cookies on that same HTML origin before replay. |
| Cold New Reddit HTML session | Recognize the direct 200 verification document, bootstrap through `https://www.reddit.com/`, then replay the original URL. The same optional browser recovery applies. |
| Any automatic bootstrap or fallback | Never use Old Reddit. |

The normal Reddit solver is browser-free. It uses the exact wreq client, cookie
jar, and TLS fingerprint that received the gate. A configured browser is only
used as a fallback when that exact parser/submit path cannot establish the
anonymous cookie set.

## Detection and solve sequence

The solver activates for either the structural Reddit 403 network-security
template or a strictly parsed 200 verification document. The 403 template
requires `theme-beta` near the beginning plus the network-security block copy.
The 200 path requires the expected title, one same-origin GET form, the exact
hidden fields, and the recognized bounded calculation and submit sequence.

```text
original Reddit request
  -> 403 JSON gate or 200 HTML verification gate
  -> cache any gate Set-Cookie headers
  -> GET https://www.reddit.com/
  -> validate and parse the recognized hidden GET form
  -> derive the one recognized seed-doubling solution
  -> submit the same-origin solved GET on the same client
  -> cache and validate response-scoped Set-Cookie names
  -> discard the solved homepage without reading its body
  -> replay the original URL once, whether JSON or HTML
```

The verification parser fails closed. It requires the expected title, one GET
form targeting the fixed New Reddit root, exactly the recognized hidden fields,
a bounded token and seed, and exactly one recognized calculation plus submit
sequence. It never evaluates served JavaScript.

If any inline leg fails and the session has `browser_solver=`, wafer performs
one browser recovery before fingerprint rotation:

```text
failed inline bootstrap
  -> navigate the browser to https://www.reddit.com/
  -> wait briefly for anonymous cookies
  -> reload that HTML root at most once
  -> require loid plus token_v2 or csv, scoped to Reddit
  -> import browser cookies without pinning the session-wide fingerprint
  -> replay the original request through wreq
```

The browser never navigates or reloads the blocked JSON URL. Browser HTML is
never returned as the response to the original request. Reddit's fixed solve
origin also takes precedence over a session-level `solve_origin`.

## Cookies and persistence

A successful solved response must itself set `loid` and either `token_v2` or
`csv`. Existing jar contents are not accepted as proof that the current solve
succeeded. Browser recovery requires the same cookie-name evidence from cookies
applicable to the Reddit solve origin. Only cookie names are examined; values
are never logged.

All Reddit bootstrap legs are persisted under the canonical `reddit.com`
`CookieCache` namespace. Session-cookie semantics are unchanged: only cookies
with an expiry survive process recreation. Identity rotation clears the
canonical namespace and any older host-specific Reddit namespaces together.

## Limits, retries, and concurrency

- The verification document is capped at 32 KiB.
- A direct verification may use up to 32 KiB and the large JSON gate up to
  256 KiB of internal challenge overhead;
  the caller's `max_response_size` still applies unchanged to the final
  response.
- The fixed browser root is likewise internal solve overhead and is never
  returned or measured against the caller's final response limit.
- Every verification leg recomputes the remaining overall request deadline.
- A successful bootstrap counts as one inline solve and consumes no fingerprint
  rotation.
- Each original request attempts the bootstrap at most once.
- A configured browser fallback runs only after inline failure and before any
  fingerprint rotation. Without a browser, failure behavior is unchanged.
- Reddit's anonymous cookies do not pin the session fingerprint, so a failed
  replay retains the normal rotation escape hatch and unrelated hosts do not
  inherit a browser-pinned transport identity.
- `AsyncSession` serializes Reddit bootstrap work with a per-session lock. A
  successful inline or browser bootstrap generation lets concurrent requests
  replay once, but only while the exact solved client generation is still
  current.
- Cancellation and deadline expiry release the async lock.

Malformed verification, non-2xx legs, missing response cookie evidence, or a
client replacement cause a safe failure or a restart on the replacement client
under the same deadline. Wafer never falls back to Old Reddit.

## Live verification

On 2026-07-28, a cold Reddit JSON request with the inline parser deliberately
forced to fail completed through the browser fallback: the browser navigated
only the fixed New Reddit root, authoritative cookies were imported, the
original JSON request replayed through wreq returned 200, no fingerprint
rotation was consumed, and the session remained unpinned.

Follow the repository request-pacing rules in `CLAUDE.md`. Use wafer directly,
an empty temporary cookie cache, and `max_rotations=0`:

1. Fetch a small Reddit JSON listing and a raw New Reddit HTML page from cold
   sessions; confirm both return real content with one inline solve.
2. Confirm the automatic legs use only `www.reddit.com`.
3. Recreate the session with the same cache, wait at least five seconds, and
   confirm both request forms succeed without another inline solve.
4. Repeat both cold-session checks with `AsyncSession`.
5. To exercise browser recovery specifically, force the inline parser leg to
   fail in a controlled test and confirm Chrome navigates only the fixed New
   Reddit root, followed by a successful wreq replay of the original URL.

If Reddit does not serve the cold gate during a run, the warm result does not
by itself validate the solver.
