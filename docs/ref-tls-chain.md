# AIA chasing: completing incomplete certificate chains

Implementation: `wafer/_aia.py`. Tests: `tests/test_aia.py`.

## The problem

A TLS server must send every certificate between its leaf and a trusted
root. Some send only the leaf. Nothing is actually wrong with the
certificate -the intermediate exists and is signed by a root in every trust
store -the server just fails to present it, so a strict client cannot build
a path and the handshake fails.

Browsers hide this. Chrome, Safari and Firefox fetch the missing certificate
from the URL the leaf names in its Authority Information Access extension,
and some also carry a cache of intermediates seen previously. The result is
a site that loads in a browser and fails in every HTTP library, which is
exactly the failure mode wafer exists to eliminate.

Measured across 13 Niagara-region municipal sites, one serves an incomplete
chain: `www.lincoln.ca`, which sends a single certificate. An earlier
estimate of "one in five" counted *certificates sent* rather than chain
completeness -`www.welland.ca` sends 2 and is complete, because leaf plus
intermediate is all that is needed when the root is in the store. The
incidence is lower than first reported; the failure is still real and
unfixable from outside wafer.

The canonical control is `incomplete-chain.badssl.com`, which sends one
certificate and needs **two** hops: its leaf chains through Let's Encrypt's
`YR2` to `Root YR`, which is cross-signed into `ISRG Root X1`. Any
leaf-only server on a current Let's Encrypt certificate needs the same two
hops, which is why the chase is not limited to one.

## What it looks like

wreq surfaces BoringSSL's verdict as an opaque nested error:

```
ConnectionFailed: Connection failed to https://www.lincoln.ca/: is_connect
error: wreq::Error { kind: Request, ... reason: "CERTIFICATE_VERIFY_FAILED",
reason_code: 125 ... }
```

Every rejected certificate produces that same string. An expired leaf, a
hostname mismatch, an untrusted root and a missing intermediate are
indistinguishable from the error alone -which is why classification is done
by examining the chain, not by parsing the message.

## The flow

Triggered from the transport error handler in `_sync.py` / `_async.py`, only
after a handshake has already failed verification, and only once per origin
per session.

1. **Probe.** Reopen the connection with verification off and read the chain
   the server sent (`get_unverified_chain()`, 3.13+; leaf only on 3.12). No
   request is issued over this connection.
2. **Classify.** Walk the presented certificates by issuer link from the leaf
   (`_path_top`) -- position on the wire is not reliable. If the top of that
   walk is already signed by a trusted root, the chain is complete and the
   failure is something else: expired, revoked, wrong hostname. Stop; that
   failure must stand.
3. **Chase.** Otherwise read the caIssuers URL from that certificate's AIA
   extension and fetch it. Repeat from the newly fetched certificate until a
   trusted root is reached, up to `_MAX_CHASE_DEPTH` (4).
4. **Verify.** Each fetched certificate must have **actually signed** the
   certificate that named it (`_directly_issued`, not a subject/issuer name
   comparison); must be a CA by basicConstraints, carry keyUsage
   `keyCertSign` when keyUsage is present, and not be barred from
   `serverAuth` by EKU (`_excludes_server_auth`); must be inside its validity
   window; must satisfy `pathLenConstraint` against the certificates actually
   below it (`_path_length_ok`, counted from the walked path rather than from
   how many certificates arrived); and must carry no name constraints
   (`_has_name_constraints`). The walk terminates only when a certificate is
   **signed by a root already in the trust store** (`_signed_by_trusted_root`).
   Every
   hop being signature-linked is what makes the whole path provable, not just
   its top -see "Why every hop is checked" below.
5. **Confirm.** Reconnect with full verification against system roots plus
   the collected certificates. If the host still does not verify, discard
   everything.
6. **Retry.** Add the certificates to a session-local `CertStore`, rebuild
   the wreq client, and retry the request on the same deadline.

## Why the verification step is not optional

Adding a certificate to a `CertStore` makes it a **trust anchor**, not a
chain link. BoringSSL will accept anything it signs without walking up to a
root. This is measurable: with the intermediate loaded, `www.lincoln.ca`
verifies at chain depth 2 (leaf, intermediate) rather than 3, because
OpenSSL anchored on the intermediate rather than continuing to DigiCert
Global Root G2.

AIA URLs are plain HTTP by RFC 5280, so an on-path attacker can answer that
fetch. Anchoring whatever comes back would convert a handshake that fails
closed into one that fails open -strictly worse than the bug being fixed.

Name-based checks do not help. An attacker controls every field of the
certificate they return, including subject and issuer, so matching the
issuer name proves nothing. Only the signature does. Once a certificate is
proven to be signed by a root in the store, anchoring it grants no authority
that root had not already delegated.

`tests/test_aia.py` generates a rogue CA carrying the real intermediate's
subject and the real root's issuer name, self-signed, and asserts it is
refused. Certificates in those tests are signed for real rather than mocked,
so deleting the signature check fails the suite rather than passing it.

## Why every hop is checked

Each collected certificate is added to the store, so each one becomes an
anchor -not only the one that reached a root. Verifying just the top of the
walk leaves a hole: an attacker answering the fetch returns `I1'` carrying
the leaf's issuer name, a CA flag, valid dates, their own key, and an AIA URL
pointing at a genuine root-signed intermediate `I2`. The walk collects `I1'`,
fetches the real `I2`, terminates at a trusted root, and anchors both. `I1'`
signed nothing, and the confirmation handshake in step 5 is no barrier -the
same on-path attacker answers it with a leaf signed by `I1'`.

Linking each hop by signature closes this. `tests/test_aia.py` builds exactly
that certificate and asserts the chase returns nothing.

## Why the top of the path is walked, not read off the end

The last certificate on the wire is not reliably the top. TLS 1.3 drops the
ordering requirement, and a common misconfiguration appends the *root* while
omitting the intermediate. Reading `chain[-1]` there finds a self-signed,
trusted certificate and concludes the chain is complete -when the piece that
matters is precisely what is missing. `_path_top` follows issuer links from
the leaf instead, so that site gets chased the way Chrome chases it.

## Why step 5 exists

Proving an intermediate is root-signed says it is safe to trust. It does not
say it was the missing piece. `expired.badssl.com` and `wrong.host.badssl.com`
both chase up to a genuine, root-signed CA; adding it enlarges the trust
store for a connection that keeps failing anyway. Without the confirmation
step, four badssl negative controls each added a certificate. With it, they
add none.

## SSRF hardening

The AIA URL comes from a certificate that has not been trusted yet, so it is
attacker-influenced input naming a URL wafer will fetch.

- Only `http` and `https` are followed. RFC 5280 permits `ldap://` and
  others; `file://` would read local disk.
- The host is resolved, and every answer must be a public address. Refusing
  only literal addresses would still allow `localhost` or an
  attacker-controlled name pointing into private space, including
  `169.254.169.254`.
- **Resolution and dialling are one step.** Validating a name and then
  letting urllib resolve it again leaves a window in which the answer can
  change; the certificate naming the URL is untrusted, so a low-TTL record
  answering public once and loopback next is well within reach.
  `_guarded_connection_factory` resolves inside the connection and dials
  those exact addresses, so every request the opener makes -- redirects
  included -- is checked at the address it actually uses. Verified against a
  live rebinding server: zero requests reached it.
- **Redirects are re-checked.** urllib follows them by default, so without
  `_GuardedRedirectHandler` the guard would apply only to the URL named in
  the certificate: a public AIA URL answering 302 to
  `http://169.254.169.254/` would walk straight past it. Every hop is
  re-validated.
- Responses are capped at `_MAX_CERT_BYTES` (64 KB).
- The whole chase is capped at `min(remaining * _MAX_BUDGET_SHARE,
  _MAX_CHASE_SECONDS)`. Per-operation caps do not bound the total: four hops
  with several caIssuers URLs each could otherwise spend the entire request
  budget, turning a `ConnectionFailed` into a `WaferTimeout` with no retries
  used.

Resolving here and again inside urllib leaves a small window where the answer
could change. That gap is why nothing fetched is trusted on the strength of
where it came from.

Behind a proxy the name lookup is skipped: the proxy resolves the name and
enforces its own egress policy, so a local answer describes neither where the
request goes nor what is reachable from there. Insisting on it would also
disable chasing outright in the egress-restricted environments that motivate
running a proxy. Literal addresses are still refused, since those name a
destination regardless of who resolves.

## Trust store handling

`_load_system_cert_pems()` in `_base.py` reads the platform bundle
(`security find-certificate` on macOS, `/etc/ssl/certs/...` on Linux,
certifi as fallback) and keeps the raw PEM bytes. Verification runs against
the same roots the TLS client was given -checking against Python's store
instead could accept an intermediate whose root wafer does not trust.

Roots are parsed one certificate at a time, not as a stack. macOS ships a
root with a non-positive serial number that `cryptography` warns about today
and intends to reject outright; parsing the stack in one call would drop
every root along with it and silently disable chasing.

## Scope and limits

- One attempt per **origin** (canonical host *and* port) per session, once a
  verdict exists. A chase that never examined the chain -- no budget left, an
  unreachable probe, an unusable trust store -- raises `ChaseInconclusive`
  and the origin is forgotten rather than recorded, so a momentary condition
  does not become a session-long outage. Otherwise, successful or not: two services on one name can present different chains.
  The claim is taken under a lock, because `AsyncSession` runs the chase in a
  worker thread and two concurrent failures on one origin would otherwise
  both proceed. Callers that arrive while a chase is in flight wait for it
  and answer from its verdict; callers that arrive after it settled get
  `False`, because the certificates are already installed and a request still
  failing cannot be helped by chasing again. Reporting success repeatedly
  spun the retry loop without consuming budget -measured at 412,474
  handshake attempts in three seconds.
- A certificate failure the chase cannot fix falls through to the ordinary
  retry path. Failing fast was tried and reverted: a certificate error is
  deterministic for one server, but a host behind several addresses can have
  a single node serving a stale certificate after a partial deploy, and a
  retry re-resolves onto a healthy one. Multi-address hosts are common
  (`www.google.com` answers with eight), so a few seconds of repeated
  handshakes is the better trade against losing that recovery.
- Anchors are re-checked for expiry on every `_cert_store()` call, not only
  when the cache is cold. A trust anchor's own validity is not enforced by
  the verifier, and after the first build the cache is invalidated only by a
  new chase, so a cache-gated check would never fire for the long sessions
  this exists to protect.
- `_cert_store()` runs entirely under `_aia_lock`, because it *writes* the
  shared certificate list as well as reading it, and every rotation and
  retirement rebuild reaches it without otherwise holding the lock. Unlocked,
  a rebuild that snapshotted the list before a chase installed a certificate
  wrote the snapshot back, erasing the proven certificate and overwriting its
  cache invalidation -- and since the origin was already recorded as
  attempted, the host stayed unreachable for the session. The lock is
  reentrant so a future caller holding it while reaching `_cert_store` fails
  visibly rather than deadlocking.
- Client publication is guarded by a generation compare-and-set, so a build
  that started before certificates landed cannot overwrite the client that
  has them.
- Credentials embedded in an http proxy URL are carried on the CONNECT as
  `Proxy-Authorization`. Without that the probe takes a 407 while the urllib
  fetch path survives (ProxyHandler reads them itself), an asymmetry that
  reads as "chasing does not work behind my proxy".
- Certificates live on the session, in memory. Nothing is written to disk and
  nothing is shared between sessions. The native-TLS transport is rebuilt when
  they change, so one host does not behave differently on two transports.
- There is no public API and no opt-out. Verification cannot be disabled.
- **Honors `resolve=` rather than skipping under it.** The probe and the
  confirmation handshake dial the pinned address with SNI intact, the same
  way `NativeTLSTransport._pin_socket` does, so the pin stays absolute and no
  DNS-rebinding window is reopened. The issuer fetch goes to a host the pin
  never covered and is guarded instead by the public-address rule in
  `_is_fetchable_url`, applied to the URL and to every redirect -the same
  class of check a pinning caller performs before pinning. Skipping under
  `resolve=` was the first design and it was wrong: fetchaller pins every
  fetch, so it would have meant the consumer that reported the bug never
  received the fix.
- **Skipped for socks and https proxies.** Plain HTTP proxies are tunnelled
  through with CONNECT; the others cannot be, here or on the native-TLS path,
  and a direct probe would leak around the operator's egress path.
- **Two extra handshakes per chase, on Python's TLS stack.** The probe and
  the confirmation each complete a stock CPython/OpenSSL handshake to the
  origin and close without sending a request, before wreq connects with the
  Chrome fingerprint. A TLS-fingerprinting WAF would see two Python
  ClientHellos followed by a Chrome one. This is a real exception to wafer's
  core invariant; it is accepted because it happens only on a host that has
  already failed verification, which in practice is a misconfigured small
  site rather than a WAF customer.
- **The probe uses CPython's TLS stack**, not wafer's browser fingerprint.
  wreq exposes the peer certificate only on a *successful* handshake, and the
  handshake in question is the one that failed, so the chain has to be read
  some other way. On a host that resets or blackholes non-browser TLS the
  probe returns nothing and the chase never starts -the one case where wafer
  can still fail on a site a browser loads. Visible at debug level only.
- **Python 3.12 loses the fast path.** `get_unverified_chain()` is 3.13+, so
  only the leaf is readable and a complete-but-otherwise-broken chain cannot
  be recognised up front. Step 5 still discards the result, so the cost is one
  wasted probe and fetch per host, not a wrong outcome.

## Cost when nothing is broken

Zero. The chase runs only after a handshake has already failed verification,
and `is_certificate_verify_failure` -the predicate that decides whether to
start -lives in `_base.py` precisely so that `wafer._aia`, and through it
`cryptography`, never loads on a session that meets no broken chain.
`cryptography` is about a third of what wafer's import would otherwise cost,
so importing it eagerly would tax every consumer for a path most never take.
`import wafer` measures the same as before this feature, and
`"cryptography" in sys.modules` is False afterwards.

## Verified

`www.lincoln.ca` -> 200 (1 intermediate, `GeoTrust TLS RSA CA G1` via
`http://cacerts.geotrust.com/GeoTrustTLSRSACAG1.crt`), sync and async, plain
and with `resolve=` pinned. `incomplete-chain.badssl.com` -> 200 (2
intermediates). Four concurrent pinned requests to one broken-chain host all
returned 200 with none starved. Through a real local HTTP proxy: 200, with
the proxy log showing every connection -probe, AIA fetch, confirmation and
both wreq attempts -and no direct egress. A bogus `resolve=` pin blackholes
the probe and adds zero certificates, proving the pin is honoured rather than
bypassed. 18 rejected handshakes leaked no sockets.
Controls `www.pelham.ca`, `www.welland.ca`, `www.thorold.ca` -> 200,
unchanged, no chase. Negative controls `expired`, `self-signed`,
`untrusted-root` and `wrong.host` on badssl.com -> all still rejected, zero
certificates added.

`www.notl.org` remains a genuine failure: it serves a certificate whose SANs
are `notl.com` and `www.notl.com` only. Chrome rejects it too. Classified as
"sent a complete chain, verification failed for another reason".
