# iOS Safari transport identity

`Profile.IOS_SAFARI` is wafer's custom, wire-verified iPhone Safari profile.
It is distinct from wreq's built-in `Emulation.SafariIos*` profiles.

## Usage

```python
from wafer import Profile, SyncSession

with SyncSession(profile=Profile.IOS_SAFARI) as session:
    response = session.get("https://example.com")
```

Pass `safari_locale="ca"` for the measured Canadian English language header:

```python
with SyncSession(
    profile=Profile.IOS_SAFARI,
    safari_locale="ca",
) as session:
    response = session.get("https://example.com")
```

The async API takes the same options.

## Capture

Captured from real iPhone Safari 26.5.2 against `tls.peet.ws` on 2026-07-26:

- UA: `Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.5.2 Mobile/15E148 Safari/604.1`
- JA3: `771,4866-4867-4865-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27,4588-29-23-24-25,0`
- JA3 hash: `ecdf4f49dd59effc439639da29186671`
- JA4: `t13d2013h2_a09f3c656075_7f0f34a4126d`
- H2: `2:0;3:100;4:2097152;9:1|10420225|0|m,s,a,p`
- H2 hash: `c52879e43202aeb92740be6e8c86ea96`
- ALPN: `h2`, then `http/1.1`
- Supported groups: X25519MLKEM768, X25519, P-256, P-384, P-521
- Key shares: X25519MLKEM768 and X25519
- Certificate compression: zlib
- Accept-Encoding: `gzip, deflate, br, zstd`

The `CPU iPhone OS 18_7` and `Version/26.5.2` tokens are intentionally kept
together. They are the real browser's output; changing the OS token to `26_5_2`
would create an invented fingerprint.

The captured request had `Sec-Fetch-Site: cross-site` and an empty Referer
because of the page's navigation context. Those values are not properties of
the device. The profile defaults to a direct top-level navigation
(`Sec-Fetch-Site: none`) and wafer's normal referer/embed logic supplies
context-specific headers.

## Runtime identity

`session.fingerprint_envelope()` reports:

```python
{
    "family": "safari",
    "emulation": "ios_safari",
    "is_mobile": True,
    "sec_ch_ua": None,
    # ...
}
```

Safari sends no Chromium Client Hints. The profile uses custom `TlsOptions`
and `Http2Options`, so `session.emulation` is `None`; use
`fingerprint_envelope()` or `response.emulation` to identify the active
profile.

## Limits

- The capture is for iPhone Safari only. It is not presented as an iPad or
  native `URLSession`/CFNetwork identity.
- Fingerprint rotation keeps this identity fixed. Retrying with desktop
  Firefox/Chrome/Edge would make the mobile UA and transport incoherent.
- The Imperva native-OpenSSL fallback is disabled for the same reason: it
  would keep the iPhone UA while replacing the captured mobile ClientHello.
- Passing `browser_solver=` or `solve_origin=` raises `ValueError`. wafer's
  browser solver is desktop Chromium, so its browser-bound cookies cannot be
  replayed coherently under this profile.
- Challenge detection still works. Without an HTTP-only inline solver, an
  unsolved browser challenge raises normally.

## Built-in wreq iOS emulations

`emulation=Emulation.SafariIos26_2` remains available for callers who need that
older identity. `Profile.IOS_SAFARI` is the capture-accurate 26.5.2 path and
does not change or alias the built-in profile.
