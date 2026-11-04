# TODO: iOS impersonation (Mobile Safari + native app) -scoping spec

**Owner:** wafer
**Status:** IOS_SAFARI COMPLETE (wire-verified, shipped). IOS_APP DEFERRED
(2026-10-08). The two blocking questions are now answered for the motivating
consumer (Reddit's iOS app API), and neither kills it. But that consumer will
not adopt a wafer profile (see "Native-app investigation" below), and a
generic profile still needs one real-iPhone capture. Do not start code work
until a consumer that can actually use wafer asks for it. This is a planning
spec, not a bug.
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

wafer should expose what it picked (iOS version and build, CFNetwork/Darwin
version, locale) read-only, mirroring the existing
`build_fingerprint_envelope()` / `resp.fingerprint` pattern
(`_fingerprint.py:988`), so a consuming repo can build coherent app headers
without duplicating the coherence table. wafer must **not** absorb UUID
minting or persistence -that is per-app schema and falls under CLAUDE.md's
"What NOT to Build". The hardware model / screen table also stays in the
consumer: it never touches the transport, only app headers.

**Integration hazard to document:** wafer's cookie cache persists per-domain
JSON under `cache_dir` (`_cookies.py:89`). A consuming repo's device UUID
needs the same lifecycle -same identity means same cookies means same device
ID. A UUID store with a different reset boundary produces a fresh device ID
replaying stale cookies, which is more incoherent than either alone.

---

## Native-app investigation against Reddit's iOS app (2026-10-08)

The motivating consumer is a private repo that talks to Reddit's API as the
official iOS app (Reddit 2026.29.0 build 634246 on iOS 26.5.2 build 23F84),
driving wreq directly. Its real-device captures (45 raw ClientHellos, 642
requests through mitmproxy) and a static scan of the IPA answer most of the
open questions. Only population-level transport facts are recorded here,
nothing per-install.

### The two blockers, for Reddit: neither kills it

- **App Attest / DeviceCheck: linked, not enforced on any path the consumer
  uses.**
  - `DCAppAttestService` is imported. No legacy `DCDevice` call.
  - Reddit's own attestation (`GET /auth/v1/attestation/challenge`,
    `POST .../register_device`, `POST .../device_token`) only runs when a
    response carries `X-Attestation-Should-Retry: true`. It never fired on
    anonymous use, signup, login, reads, votes, saves or comments.
  - The real app sends a cached `x-attestation-device-token` on the session
    access-token request. Leaving it out is accepted.
  - Google's reCAPTCHA Enterprise SDK (required on register and login) uses
    App Attest conditionally. In the iOS Simulator App Attest reports
    unsupported and the SDK takes a no-attestation path.
  - If Reddit ever makes attestation mandatory for its client id, the whole
    approach dies. No transport profile can fix that.
- **Mobile WAF SDK: none found.**
  - The IPA bundles only `ExtensionDependencies.framework` and
    `Lottie.framework`.
  - A strings scan finds no DataDome, HUMAN/PX, Kasada, Akamai BMP, Shape/F5,
    Imperva, Arkose or ThreatMetrix. Negative static evidence only; an
    obfuscated SDK could evade it.
  - The GraphQL host (`gql-fed.reddit.com`) sits behind Cloudflare and lets the
    app's TLS fingerprint through. Other servers are `snooserv` / `envoy`.

### Captured CFNetwork transport (iOS 26.5.2, real device)

- **Two ClientHellos per app.**
  - API hello (13 ciphers):
    - Ciphers `1302 1301 1303 c02c c030 c02b cca9 c02f cca8 c00a c009 c014 c013`.
    - Everything else matches `Profile.IOS_SAFARI`'s hello: extension order
      `0,23,65281,10,11,16,5,13,18,51,45,43,27` (fixed, identical in all 45
      hellos), groups X25519MLKEM768 / x25519 / P-256 / P-384 / P-521, key
      shares X25519MLKEM768 + x25519, the same sigalgs with the duplicated
      `0805`, ALPN h2 + http/1.1, zlib certificate compression, GREASE.
    - JA3 `8527da8b8a640065e72ec6b6f99764f3`, JA4
      `t13d1313h2_f57a46bbacb6_7f0f34a4126d`.
  - Media hello (20 ciphers): JA4 `t13d2013h2_a09f3c656075_7f0f34a4126d`,
    the same hello as `Profile.IOS_SAFARI`.
  - **Hypothesis, untested:** the 13-cipher hello is App Transport Security's
    forward-secrecy-only set, and the 20-cipher hello is what ATS-exempt loads
    send (the app sets `NSAllowsArbitraryLoadsForMedia`, and v.redd.it via
    AVPlayer gets the 20-cipher hello). If true, the 13-cipher hello is shared
    by every ATS-enforced iOS 26.5 app, which is what makes a generic profile
    possible at all.
- **HTTP/2: NOT captured on iOS.**
  - The consumer's `2:0;4:4194304;3:100;9:1|10485760|0|m,s,p,a` came from
    **macOS** URLSession, not an iPhone.
  - iOS Safari (`4:2097152`, `m,s,a,p`) and macOS Safari (`4:6291456`) differ
    from each other and from macOS URLSession, so the iOS URLSession value
    cannot be assumed.
- **Default headers:**
  - Bare GETs: `accept, user-agent, priority, accept-language,
    accept-encoding`, in that order.
  - `accept-encoding: gzip, deflate, br` (no zstd, unlike Safari).
  - `accept-language` in the CFNetwork shape `<ll-RR>,en-US;q=0.9,en;q=0.8`.
  - `priority: u=3`, sometimes `u=3, i`.
  - No Sec-Fetch, no Referer.
  - Header order on API requests with many app headers is non-deterministic.
- **CFNetwork / Darwin / iOS mapping: one row.**
  - iOS 26.5.2 (23F84) = `CFNetwork/3860.600.12 Darwin/25.5.0`.
  - Default UA format `<bundle name>/<CFBundleVersion> CFNetwork/x Darwin/y`.
- **HTTP/3: likely used, and wreq cannot do it.**
  - Media hosts advertise `alt-svc: h3=":443";ma=2592000;persist=1`; the
    gql-fed, www and e.reddit hosts do not.
  - The binary has an `ios_graphql_http3` experiment and uses
    `URLRequest.assumesHTTP3Capable`.
  - Everything was captured through mitmproxy as HTTP/2, so actual QUIC use on
    a real phone is unconfirmed.
- **Alamofire vs bare URLSession: answered.** The app's HTTP libraries
  (AFNetworking, Apollo iOS, Nuke, PINRemoteImage) all sit on URLSession; no
  Swift Alamofire. One identical API hello across every API host suggests the
  wrappers don't change TLS. They do shape app-level headers (AFNetworking's
  UA template and `en-US;q=1` Accept-Language).

### Can wreq 0.13 express it

- **TLS: yes.** Every field needed exists in `TlsOptions`; `IOS_SAFARI` already
  uses the same field set on 0.13. The 13-cipher hello was only wire-checked
  on wreq 0.12.1 and needs a fresh check on 0.13.
- **HTTP/2: yes.** `settings_order`, `headers_pseudo_order`,
  `no_rfc7540_priorities` and `initial_connection_window_size` all exist (the
  connection window is the total, i.e. captured increment + 65535).
- **Cannot:** HTTP/3 / QUIC (no transport, only an ALPN token); TLS
  record-layer version (unknown anyway: the `160303` prefix in the captured
  bytes is synthesized by mitmproxy).
- **Use `permute_extensions=False`.** Apple never reorders extensions.
  `_ios.py` and `_safari.py` pass `True` alongside an explicit
  `extension_permutation`; the live JA3 assertions show the explicit order
  wins, but `IOS_APP` should state the intent directly, as `_dart.py` does.

### Why not build it now

- **That consumer won't use it.** Its rules forbid depending on wafer, and it
  pins `wreq==0.12.1`, which cannot coexist with wafer's `wreq>=0.13,<0.14`.
- **It needs things a wafer session doesn't model:** switching between the two
  hellos per connection inside one identity, `interface=` binding, iOS cookie
  semantics (session cookies dropped on restart), and zero retries.
- **wafer already reads Reddit** through its Android-app route
  (`docs/ref-reddit.md`).
- **A generic profile is still blocked** on iOS HTTP/2 and the unproven ATS
  hypothesis.

---

## What we DON'T know

### Native-app blockers (must resolve per target before `Profile.IOS_APP`)

- [x] **Does the target use App Attest / DeviceCheck?** For Reddit: linked
      but not enforced on the paths used (see investigation above). For other
      targets it is still a per-target question, and a required
      `DCAppAttestService` assertion still kills the project for that target:
      the key is Secure Enclave-bound and hardware-attested by Apple, so it
      cannot be synthesized or extracted.
- [x] **Does the target use a mobile WAF SDK** (DataDome mobile, PX mobile,
      Kasada mobile)? For Reddit: none found (static scan). For other targets
      still per-target. Their payloads are SDK-signed; none of wafer's
      existing solvers apply. Would be a new solver family, not a profile.

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

### iOS app / CFNetwork specifics

- [x] The TLS shape (iOS 26.5.2): both hellos captured, see investigation.
- [ ] **HTTP/2 on an iPhone.** Only macOS URLSession has been captured.
- [ ] **Whether the 13-cipher hello is ATS-generic** or specific to the app.
- [ ] The CFNetwork <-> Darwin <-> iOS version mapping table. One row
      captured (26.5.2 / 23F84 / 3860.600.12 / 25.5.0); every other release
      needs its own capture.
- [ ] Default NSURLSession headers: order, encoding and Accept-Language shape
      captured. Still unknown: which `priority` a plain dataTask sends, and
      which headers CFNetwork adds itself versus the app.
- [ ] **HTTP/3.** Likely used for media hosts (and GraphQL behind an
      experiment flag). wreq is h1/h2 only, so declining QUIC is a signal we
      cannot fix.
- [ ] TLS session resumption: none of the 45 captured hellos carries a PSK.
- [x] Alamofire vs bare URLSession: libraries all sit on URLSession; one API
      hello across every API host.

### Capture method

One capture unblocks the generic profile: on a real iPhone with no proxy, a
minimal app running one plain `URLSession.shared.dataTask` with default ATS
against `tls.peet.ws/api/all`, then again with `NSAllowsArbitraryLoads`.
Record JA4, the H2 fingerprint, the header frame (order and `priority`), the
UA, and whether any UDP/443 traffic appears.

- [ ] **iOS Shortcuts' "Get Contents of URL" runs on NSURLSession**, so it may
      substitute for the minimal app with zero code and zero app-signing.
      Needs confirming that Shortcuts does not add its own UA or route through
      a different stack.
- [ ] The iOS Simulator would be cheaper still, but needs one device
      comparison before its values can be trusted.
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

### Tier 2 -`Profile.IOS_APP` (CFNetwork): DEFERRED, ~1 day once unblocked

Start only when (a) a consumer that can depend on wafer asks for it, and
(b) the iPhone capture above has run.

1. `wafer/_ios_app.py`, shaped like `_dart.py` (99 lines):
   - ATS 13-cipher hello by default, with an option for the non-ATS hello that
     reuses `_ios.py`'s constants. `permute_extensions=False`.
   - H2 only from the iPhone capture, never the macOS URLSession value.
   - Headers `accept: */*`, `user-agent`, `priority`, CFNetwork
     `accept-language`, `accept-encoding: gzip, deflate, br`, in the captured
     order.
   - A release table holding only captured rows, starting with
     26.5.2 / 23F84 / CFNetwork 3860.600.12 / Darwin 25.5.0.
2. API:
   - `Profile.IOS_APP`.
   - `user_agent=` (or app name/build params) defaulting to the CFNetwork form
     `<App>/<build> CFNetwork/x Darwin/y`. Real apps set their own UA.
   - `fingerprint_envelope()` reports iOS version and build, CFNetwork and
     Darwin versions, locale, ATS mode and `is_mobile: True`.
3. Guards (each one silently destroys the identity if missed):
   - Reject `embed=`, as `Profile.DART` does (`_base.py:913`).
   - Reject `browser_solver=` and `solve_origin=`, as `Profile.IOS_SAFARI`
     does (`_base.py:980`, `_base.py:1143`).
   - Disable the native-OpenSSL fallback (`_base.py:2682`).
   - No auto-Referer (`_base.py:1663`).
   - Disable the Reddit app route (`_base.py:884`), or anonymous
     oauth.reddit.com GETs go out with the Android/Chromium identity. See the
     open decision below.
4. Tests: `tests/test_ios_app.py` recomputing JA3/JA4 from the constants for
   both hellos, exact kwargs, every guard, the envelope, the Reddit route off,
   plus a scrapfly live test behind `WAFER_LIVE=1`. Update `llms.txt`,
   `README.md` and `docs/ref-ios.md`.
5. Known permanent gaps: HTTP/3, TLS session resumption, and a new device
   capture for every iOS release.

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

## Open decision: the Reddit app route ignores the session profile

`_reddit_app_enabled` (`_base.py:884`) is on for every profile except
`OPERA_MINI`. A session built with `Profile.SAFARI`, `Profile.IOS_SAFARI` or
`Profile.DART` therefore sends its anonymous Reddit JSON reads as the Android
Reddit app, not as the identity the caller chose. Either that is intended
(the route is a separate app install with its own identity, and the caller
only asked for the data) and should be documented in `llms.txt`, or the route
should be limited to the default Chrome profile. Needs a decision before
`IOS_APP` adds another profile to the list.

---

## Estimate

The iPhone Safari tier is complete. `Profile.IOS_APP` is about a day once a
wafer consumer asks for it and the iPhone URLSession capture has run.
