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
it: the existing `_try_browser_solve` runs a real browser, earns the `reese84`
token, and injects it into wreq's jar; wreq then carries the token through the
rest of the session (the token is accepted cross-TLS, verified live: a
browser-earned `reese84` replays on a plain OpenSSL connection -> 200). This is
exactly how a real browser survives heavy usage (earn the token once on the
site, replay it on every XHR). So: light usage is no-browser (the free pass or
wreq's own 302-cookie dance); heavy usage browser-solves `reese84` once and then
reuses it. Both the unpinned-trigger and pinned-sticky paths reach this same
escalation.

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
