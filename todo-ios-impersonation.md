# TODO: iOS impersonation (Mobile Safari + native app) -scoping spec

**Owner:** wafer
**Status:** PARTIAL. `Profile.IOS_SAFARI` was implemented from a real iPhone
Safari 26.5.2 capture on 2026-07-26. `Profile.IOS_APP` is not started.
Earlier wreq measurements were taken against tools.scrapfly.io; the real
device capture was taken against tls.peet.ws.
**Goal:** an iPhone Mobile Safari identity (`Profile.IOS_SAFARI`, complete)
and a future native-app identity (`Profile.IOS_APP`, NSURLSession / CFNetwork)
alongside the existing `SAFARI` / `DART` / `OPERA_MINI` profiles. iPad remains
separate until it has its own real-device capture.

---

## What we KNOW

### wreq already ships mobile Apple profiles, and wafer already routes them

`dir(wreq.Emulation)` (wreq 0.12.1, 134 profiles) exposes:

```
SafariIos16_5, SafariIos17_2, SafariIos17_4_1, SafariIos18_1_1,
SafariIos26, SafariIos26_2, SafariIPad18, SafariIPad26, SafariIpad26_2
FirefoxAndroid135, OkHttp3_9 ... OkHttp5     (Android, not relevant here)
```

There is **no mobile Chromium profile** in wreq, so there is no path to an
"iOS Chrome" identity (which on a real device is WebKit anyway).

wafer already handles these correctly without any change:

- `emulation_family()` (`_fingerprint.py:490`) classifies `SafariIos*` /
  `SafariIPad*` / `SafariIpad*` into the `safari` family via the optional
  variant token in `_FAMILY_RE`, so they get the WebKit navigation envelope
  (`_SAFARI_ACCEPT`, `q=0.9`, `gzip, deflate, br`, no client hints) rather
  than Chrome's `DEFAULT_HEADERS`.
- `emulation_is_mobile()` (`_fingerprint.py:525`) already returns `True` for
  them via `_MOBILE_RE`.
- `build_fingerprint_envelope()` already stamps `is_mobile: True` and leaves
  all `sec_ch_ua*` as `None` (correct: WebKit has no client hints).

**So `wafer.SyncSession(emulation=wreq.Emulation.SafariIos26_2)` is a working
iPhone impersonation today, at zero effort.** The work below is about making
it *accurate* and making it first-class.

### Measured wire output (2026-07-26, tools.scrapfly.io/api/fp/anything)

| identity | UA | akamai H2 | ja3 curves |
|---|---|---|---|
| `SafariIos26_2` | `Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.2 Mobile/15E148 Safari/604.1` | `2:0;3:100;4:2097152;9:1\|10420225\|0\|m,s,a,p` | `4588-29-23-24-25` |
| `SafariIpad26_2` | `Mozilla/5.0 (iPad; CPU OS 18_7 like Mac OS X) ... Version/26.2 Mobile/15E148 Safari/604.1` | `2:0;3:100;4:2097152;9:1\|10420225\|0\|m,s,a,p` | `4588-29-23-24-25` |
| `Profile.SAFARI` (wafer's wire-verified desktop) | `... (Macintosh; Intel Mac OS X 10_15_7) ... Version/26.3 Safari/605.1.15` | `2:0;3:100;4:6291456;9:1\|8290305\|0\|m,s,a,p` | `4588-29-23-24` |

Headers sent on the iOS profiles (correct, inherited from the `safari`
family envelope): `accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8`,
`accept-encoding: gzip, deflate, br`, `accept-language: en-US,en;q=0.9`,
`priority: u=0, i`, `sec-fetch-dest/mode/site`.

### Earlier suspected wreq defects resolved by the real capture

The real Safari 26.5.2 UA also sends `CPU iPhone OS 18_7`; Apple has frozen
that UA component, so the apparent version mismatch is correct. The real
supported-groups list also includes P-521. Neither is a defect.

### The H2 shape is verified and differentiated

iOS reports `4:2097152 / conn 10420225` vs desktop's `6291456 / 8290305`.
The real-device capture confirms the mobile values.

### iOS Safari implementation status

- `Profile.IOS_SAFARI` is wired through the shared sync/async session path.
- `fingerprint_envelope()` reports family `safari`, emulation `ios_safari`,
  and `is_mobile: True`.
- The profile keeps one coherent identity through retries and rotations.
- `browser_solver=` and `solve_origin=` are rejected at construction because
  the available solver is desktop Chromium.
- Regression tests, `llms.txt`, `README.md`, and `docs/ref-ios.md` are updated.

### Why solving challenges *as* iOS is out of scope

The solver is Patchright **Blink** on macOS. Presenting it as Mobile Safari
means lying about `navigator.vendor`, WebGL renderer (Apple GPU),
`maxTouchPoints`, DeviceMotion/DeviceOrientation, `navigator.standalone`,
screen 393x852@3, absent `window.chrome`, and WebKit-only JS/CSS quirks.
`docs/ref-headless.md` documents mass native-API override as *harmful* and
detectable via `toString()`. This would add exactly the detection vector
wafer deliberately avoids.

Real-WebKit alternatives (iOS Simulator Mobile Safari over the WebKit
Inspector protocol, or `safaridriver` on macOS) do not speak CDP, so none of
the existing machinery carries over: no `Page.addScriptToEvaluateOnNewDocument`
init scripts, no drag replay, no per-WAF solvers. That is a second solver
backend, not a profile.

For app targets it is moot anyway: DataDome / PerimeterX / Kasada mobile SDKs
sign payloads natively rather than issuing browser cookies.

### Privacy / device-identity boundary (settled)

**Nothing in the wafer half is identifying.** A TLS ClientHello carries cipher
suites, curves, extensions, ALPN, SNI. The CFNetwork UA carries iOS version
and CFNetwork/Darwin build. Neither contains device identity. A capture from a
real iPhone yields the *population* value for that iOS build, identical across
every device on it. Safe to commit.

The capture that *is* sensitive is a different activity: mitmproxying a real
app to learn its header schema produces IDFV, keychain install IDs, push
tokens, bearer tokens, receipt data. That goes in neither wafer nor the
consuming repo.

Reusing a real personal device ID is also wrong *operationally*, before it is
a privacy issue. Most app device IDs (`x-device-id`, `x-install-id`, IDFV) are
client-generated UUIDs written to the keychain at first launch. Reusing one
across many sessions correlates all that traffic to a single install, which is
the linkability mobile WAFs look for. Fresh UUID per identity is both safer
and better cover.

**The line:**

| layer | owner | contents |
|---|---|---|
| transport identity | **wafer** | TLS options, H2 options, CFNetwork/Darwin UA, device-coherence table. Population-generic, no secrets. |
| app identity | **consuming repo** | app header schema, device/install UUIDs, auth tokens. Per-target, per-install. |

wafer should expose what it picked (model, iOS version, CFNetwork/Darwin
version, screen metrics, locale) read-only, mirroring the existing
`build_fingerprint_envelope()` / `resp.fingerprint` pattern
(`_fingerprint.py:988`), so a consuming repo can build coherent app headers
without duplicating the coherence table. wafer must **not** absorb UUID
minting or persistence -that is per-app schema and falls under CLAUDE.md's
"What NOT to Build".

**Integration hazard to document:** wafer's cookie cache persists per-domain
JSON under `cache_dir` (`_cookies.py:89`). A consuming repo's device UUID
needs the same lifecycle -same identity means same cookies means same device
ID. A UUID store with a different reset boundary produces a fresh device ID
replaying stale cookies, which is more incoherent than either alone.

---

## What we DON'T know

### Native-app blockers (must resolve before `Profile.IOS_APP`)

- [ ] **Does the target use App Attest / DeviceCheck?** If the endpoint
      requires a `DCAppAttestService` assertion, the key is Secure
      Enclave-bound and hardware-attested by Apple. It cannot be synthesized,
      and it cannot be extracted from our own phone either. The only way it
      works is generating real assertions on a real device, which is exactly
      the personal-identity exposure we are avoiding. **This kills the
      project for that target regardless of TLS quality.**
- [ ] **Does the target use a mobile WAF SDK** (DataDome mobile, PX mobile,
      Kasada mobile)? Their payloads are SDK-signed; none of wafer's existing
      solvers apply. Would be a new solver family, not a profile.
- [ ] Both of the above are answerable in an afternoon by watching one real
      app session, and both can kill the work, so resolve them before the
      ~2 days of profile implementation.

### iOS Safari specifics

- [x] `4:2097152 / conn 10420225` verified on a real iPhone.
- [x] Real UA verified: OS token `18_7`, Safari `26.5.2`,
      `Mobile/15E148`, trailing `Safari/604.1`.
- [x] TLS cipher, extension, signature, curve, and key-share shapes captured.
- [ ] Whether iPad differs from iPhone on the wire at all beyond the UA.
      wreq emits identical H2 and curves for both; unknown whether that is
      accurate or just wreq reusing one config.
- [x] iOS Safari sends `priority: u=0, i`.
- [x] Correct cipher list ordering captured.

### iOS app / CFNetwork specifics (entirely unknown)

- [ ] The whole TLS shape. NSURLSession goes through Network.framework's
      BoringSSL fork, which is a different stack from WebKit's. Nothing about
      it has been measured.
- [ ] The CFNetwork <-> Darwin <-> iOS version mapping table (needed the way
      `_CHROME_BUILDS` is needed for Chrome full-version hints).
- [ ] Default NSURLSession header set and ordering (assumed `Accept: */*`,
      `Accept-Encoding: gzip, deflate, br`, `Accept-Language` from device
      locale, no Sec-Fetch, but unconfirmed).
- [ ] **HTTP/3.** Many iOS apps negotiate h3. wreq is h1/h2 only (needs
      confirming). If a target is h3-preferring, declining QUIC is itself a
      signal, and we have no way to fix it.
- [ ] Whether Alamofire deviates from bare NSURLSession on the wire (assumed
      not -it wraps URLSession -but unconfirmed).

### Capture method (proposed, untested)

- [ ] **iOS Shortcuts' "Get Contents of URL" runs on NSURLSession**, so it
      should yield a real CFNetwork fingerprint from a personal iPhone with
      zero code and zero app-signing. Needs confirming that Shortcuts does
      not add its own UA or route through a different stack.
- [x] Safari on the iPhone pointed at a fingerprint endpoint produced the
      IOS_SAFARI capture.
- [ ] The configured wreq/system trust path currently rejects tls.peet.ws with
      `CERTIFICATE_VERIFY_FAILED`. Use `tools.scrapfly.io/api/fp/anything` for
      routine live regression tests. Scrapfly does not include JA4, so the
      one-off peet comparison requires an explicitly unverified diagnostic
      client and must never carry secrets.

---

## Plan

Ordered by value-per-day. Tier 0 already works; Tier 3 is explicitly declined.

### Tier 0 -document what already works: COMPLETE

`llms.txt` and `docs/ref-ios.md` document both the built-in
`Emulation.SafariIos26_2` path and the capture-accurate custom profile.

### Tier 2 (pending) -`Profile.IOS_APP` (CFNetwork), ~1 day

Highest value, least code, and mobile API endpoints are typically defended far
more weakly than the web properties in front of them.

1. Resolve the two blocking questions above.
2. Capture a real CFNetwork fingerprint via iOS Shortcuts.
3. `wafer/_ios_app.py` shaped exactly like `_dart.py` (99 lines): custom
   `TlsOptions`, minimal `client_headers()`, no browser envelope to get right.
4. CFNetwork/Darwin/iOS coherence table.
5. `user_agent=` session param -real apps set their own UA, so the default
   `App/1.0 CFNetwork/x Darwin/y` form must be overridable.
6. Guard browser solve the way `Profile.DART` guards embed mode
   (`_base.py:536`): raise a clear error rather than silently solving as
   desktop Chrome and destroying the identity.
7. Expose the device envelope (see privacy section) so consuming repos can
   build coherent app headers.

### Tier 1 -`Profile.IOS_SAFARI`: COMPLETE

1. Captured real iPhone Safari 26.5.2 against tls.peet.ws.
2. Added wire-verified `TlsOptions`, `Http2Options`, and navigation headers.
   The measured profile includes P-521 and the frozen `18_7` UA token.
3. Added a release-coherence record for Safari version, OS UA token, and
   Mobile build without inventing an uncaptured hardware model.
4. Made `fingerprint_envelope()` profile-aware (`is_mobile: True`).
5. Rejected desktop-Chromium browser solving and native-OpenSSL fallback so
   neither can silently destroy the mobile transport identity.
6. Added sync/async/unit/live regression coverage and updated
   `docs/ref-ios.md`, `README.md`, and `llms.txt`.

### Tier 3 -solving challenges as iOS: DECLINED

See "Why solving challenges as iOS is out of scope". Revisit only if a target
demands it, and then as a separate WebKit solver backend, not as part of these
profiles.

---

## Estimate

The iPhone Safari tier is complete. `Profile.IOS_APP` remains conditional on
the native-app blocking questions and a separate CFNetwork capture.
