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

Measured on Niagara-region municipal sites, roughly one in five serves an
incomplete chain. `www.lincoln.ca` sends 1 certificate; `www.welland.ca`
sends 2; `www.notl.org`, `www.pelham.ca` and `www.thorold.ca` send 3.

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
after a handshake has already failed verification, and only once per
hostname per session.

1. **Probe.** Reopen the connection with verification off and read the chain
   the server sent (`get_unverified_chain()`, 3.13+; leaf only on 3.12). No
   request is issued over this connection.
2. **Classify.** If the deepest certificate the server sent is already signed
   by a trusted root, the chain is complete and the failure is something
   else -expired, revoked, wrong hostname. Stop; that failure must stand.
3. **Chase.** Otherwise read the caIssuers URL from that certificate's AIA
   extension and fetch it. Repeat from the newly fetched certificate until a
   trusted root is reached, up to `_MAX_CHASE_DEPTH` (4).
4. **Verify.** Each fetched certificate must be the issuer the previous one
   names, must be a CA (basicConstraints), must be inside its validity
   window, and must be **signed by a root already in the trust store**
   (`_signed_by_trusted_root`, using `verify_directly_issued_by`).
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
- Responses are capped at `_MAX_CERT_BYTES` (64 KB).
- Probe and fetch each take a slice of the caller's remaining budget, so a
  stalled CA endpoint cannot consume the deadline the retry still needs.

Resolving here and again inside urllib leaves a small window where the answer
could change. That gap is why nothing fetched is trusted on the strength of
where it came from.

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

## Scope

- One attempt per hostname per session, successful or not.
- Certificates live on the session, in memory. Nothing is written to disk and
  nothing is shared between sessions.
- There is no public API and no opt-out. Verification cannot be disabled.

## Verified

`www.lincoln.ca` -> 200 (1 intermediate, `GeoTrust TLS RSA CA G1` via
`http://cacerts.geotrust.com/GeoTrustTLSRSACAG1.crt`), sync and async.
Controls `www.pelham.ca`, `www.welland.ca`, `www.thorold.ca` -> 200,
unchanged, no chase. Negative controls `expired`, `self-signed`,
`untrusted-root` and `wrong.host` on badssl.com -> all still rejected, zero
certificates added.

`www.notl.org` remains a genuine failure: it serves a certificate whose SANs
are `notl.com` and `www.notl.com` only. Chrome rejects it too. Classified as
"sent a complete chain, verification failed for another reason".
