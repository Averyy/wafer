# Imperva / Incapsula

Imperva (formerly Incapsula) shows up two different ways, and wafer handles
each differently. Detection is shared; the solve path is not.

## Detection (`wafer/_challenge.py`)

`ChallengeType.IMPERVA` is raised for any of:

- **403/429** with a `reese84` or `___utmvc` cookie, OR `x-cdn: incapsula|imperva`
  (header fast path).
- **403/429** body markers: `incapsula` / `imperva`.
- **HTTP 200 interstitial** (the "Pardon Our Interruption" page): body contains
  `_incapsula_resource` AND either a tiny body (<5KB) or an interstitial-only JS
  hook (`reeseskipexpirationcheck`, `__imperva_interstitial_started__`,
  `id="interstitial-inprogress"`, `x-spa-interstitial`). The extra hook gate
  matters: the `_Incapsula_Resource` loader also appears on real protected pages
  (they embed the reese84 sensor via the same path), so matching it alone would
  re-detect a challenge after a successful solve and loop forever. Never relax
  this to "marker present" -see the same false-positive class on wellfound's
  `ddjskey` (`docs/site-list.md`).

## Two solve paths

### 1. reese84 JS challenge -> browser solve (`wafer/browser/_imperva.py`)

The classic case: the site serves a JS challenge that a real browser passes by
running the reese84 sensor, which sets/updates a solve cookie. `wait_for_imperva`
drives a real browser, replays human-like movement, and polls for the solve
cookie (`reese84` / `___utmvc` / `incap_ses_*`) to appear or change, then the
request is replayed. Live: amadeus, hkbea, appdev.pwc.com, realtor.**ca** (the
www site).

**API hosts -> solve on the origin page, not the API URL (`imperva_embedder`).**
A top-level navigation to an *API* host (e.g. `api2.realtor.ca/Location.svc/...`)
is something no real browser does, and Imperva answers it with its interactive
"Error 15" block ("Access Denied / Error 15 / I'm not a robot", Incapsula
`edet=15`) - for the deep path *and* the host root. A real browser only ever
touches an API host via same-site XHR from the site's main page. So before
navigating, the solve calls `imperva_embedder(url, headers)`:

- If the request carried a `Referer`/`Origin` that is same-site but a different
  host than the target (i.e. it was a cross-host XHR), navigate that origin - the
  actual embedder the consuming app uses.
- Else, for a non-www subdomain (an API host), fall back to `https://www.<reg>/`.
- Else (the target is already a normal page like www.realtor.ca / amadeus /
  hkbea) return `None`, keeping the legacy direct-navigation behaviour.

`solve_imperva_embedder` then loads that origin (which passes the WAF as a normal
navigation) and earns the `.<registrable>` reese84/incap cookies. From there the
original request is satisfied two ways, strongest first:

1. **In-page same-site XHR passthrough (`imperva_xhr_replay`).** While still on
   the embedder page, the solve replays the original request (GET *or* POST, via
   the `replay={method,body,content_type}` descriptor) as a `fetch(..., {
   credentials:'include'})` - a real-browser same-site XHR. A 2xx is the exact
   bytes a browser would get, returned to the caller as a passthrough response.
   Verified live: SubAreaSearch GET -> 200, PropertySearch_Post POST -> 200 with
   the full result set.
2. **Cookie replay (fallback).** If the XHR can't be captured, the earned cookies
   - injected into wreq's jar and seeded into the native jar - carry the request
   on the normal retry. They replay cross-host and cross-TLS (verified live: 200
   over native-TLS and wreq).

Either way a GET or POST to the API host succeeds, and the harvested cookies keep
the rest of the session working.

> Historical note: this "Error 15" page was once misfiled as an unsolved
> *interactive checkbox* needing a clicker. It is not a challenge real users see -
> it only appeared because wafer's own solve navigated top-level to the API host.
> Building a checkbox solver would have automated defeating a self-inflicted
> block. The fix is to stop producing the non-browser request shape.

**Generalized as `solve_origin=` (any challenge type).** This origin-page solve
is no longer Imperva-only. The session-level `solve_origin=` parameter exposes
the same mechanism for **every** WAF: set it to the site's real page and the
auto-solve navigates there to earn the token, then replays the cookies to the
API host. When `solve_origin` is set it is used as the navigation target for any
challenge; the Imperva-specific `imperva_embedder` heuristic above still runs as
the fallback when `solve_origin` is None. An explicit `solve_origin` therefore
**overrides** the Imperva auto-derivation. Use it for any JSON/XHR API that can't
be top-navigated (see the README "Browser Solving" section and `llms.txt`).

### 2. TLS-stack fingerprinting -> native-TLS bypass (`wafer/_native_tls.py`)

Some Imperva deployments fingerprint the **TLS stack itself** and challenge
*every* BoringSSL client -which is what wreq is, for all Chrome/Safari/Edge
emulations. Rotating fingerprints cannot help (same TLS library), and the WAF
cookies are not the proof it wants. A generic OpenSSL client (curl, Python
stdlib) sending the bare "API client" header set (UA + Origin + Referer +
Accept, **no `Sec-Fetch-*`**) is waved through. Live: `api2.realtor.ca`.

`NativeTLSTransport` drives stdlib `http.client` over system OpenSSL to send a
**curl-byte-identical** request: `Host` first, no `Accept-Encoding: identity`,
no `Connection: close`, no `Sec-Fetch-*`/`Sec-Ch-Ua`/`Accept-Language`. (urllib
was rejected because it emits exactly those urllib tells; under WAF rate
pressure Imperva flags them, especially on POSTs.)

Wiring in the request loop (`_async.py` / `_sync.py`):

- **Trigger:** on `IMPERVA` detection (and only when `_native_tls_usable()` -
  no proxy or an `http://` proxy), probe the native transport once. If it
  returns a non-challenge response, **pin** the host (`_native_tls_domains`) and
  return. If it is also challenged and a `browser_solver` is set, exhaust the
  rotation budget so the next wreq attempt goes straight to the last-resort
  browser solve - fingerprint rotation can never help an Imperva TLS-stack
  challenge (Safari is BoringSSL too, and re-challenged).
- **Sticky:** a pinned host routes straight to native (wreq stays challenged in
  the free-pass state, and the WAF cookies live in the native jar). A challenge
  on a pinned host is first treated as transient rate-limiting: back off and
  retry native up to `NATIVE_MAX_RETRIES`. If it persists (the heavy reese84
  state) and a `browser_solver` is set, un-pin, exhaust rotations, and fall
  through to the wreq path -> browser solve (below). With no `browser_solver`
  (and `max_rotations>0`) the exhausted native path raises `ChallengeDetected`.

### Heavy state: reese84 token, earned once, reused

Under heavy load the WAF revokes the OpenSSL free pass and demands the
`reese84` JS token from everyone. The browser DataDome-style escalation handles
it: `_try_browser_solve` runs a real browser - solving on the **origin page**
(`imperva_embedder`, above), never the API host directly - earns the `reese84`
token, and injects it into wreq's jar; wreq then carries the token through the
rest of the session (the token is accepted cross-TLS, verified live: a
browser-earned `reese84` replays on a plain OpenSSL connection -> 200). This is
exactly how a real browser survives heavy usage (earn the token once on the
site, replay it on every XHR). So: light usage is no-browser (the free pass or
wreq's own 302-cookie dance); heavy usage browser-solves `reese84` once and then
reuses it. Both the unpinned-trigger and pinned-sticky paths reach this same
escalation.

The earned cookies are also seeded into the native jar (`add_cookies`) so a later
native probe carries the token, but the host is **not** re-pinned to native right
after the solve: the solve only fires under escalation, where native itself is
challenged and wreq carries the token. Re-pinning would just burn the native
retry budget before falling back to wreq. The existing per-request native probe
re-pins later if/when the free pass returns. (Aside: the escalation here is
largely per-session-jar, not purely per-IP - a fresh session free-passes even
while another from the same IP is throttled, so the browser path is rarely hit.)

Properties: per-host sticky, per-session cookie jar, follows redirects, handles
GET/POST (`form`/`json`/`body`). Proxy handling: with no proxy or an `http://`
proxy the native path is used (an http proxy is honored via CONNECT tunnelling);
with a `socks://`/`https://` proxy (which `http.client` can't tunnel without
leaking the real IP) `_native_tls_usable()` returns False, so the trigger skips
native entirely and the challenge is handled on the proxy-aware wreq path.

## Gotchas

- `Emulation` profiles cannot escape this: every wreq profile is BoringSSL.
- Replaying the WAF cookies through wreq does **not** help -verified: curl's
  freshly-earned `visid_incap`/`nlbi`/`incap_ses` cookies still 403 on wreq.
- The native bypass depends on the WAF giving non-browser clients a free pass.
  When it doesn't (e.g. appdev.pwc.com serves the reese84 interstitial to curl
  too), the probe is correctly *not* pinned and the browser solver takes over.
- Do not rapid-fire: api2 escalates to a rate-based reese84 page that challenges
  even OpenSSL; it recovers after a cooldown, and the sticky path backs off.
