# wreq Reference

Wafer wraps wreq **0.13.0+** (the `Emulation` API, formerly rnet).

## TlsOptions Silent Failure

**`TlsOptions(**kwargs)`, `Http2Options(**kwargs)`, AND `wreq.Client(**kwargs)` / `wreq.blocking.Client(**kwargs)` all silently accept ANY kwargs -including typos and wrong names.** There is no validation and no error. A kwarg being "accepted" means nothing. Only wire / behavior verification proves it works. Authoritative kwarg names are in the `.pyi` stubs' `Params` / `ClientConfig` TypedDicts.

Concrete example: `wreq.blocking.Client(verify=False).get("https://expired.badssl.com/")` raises an SSL error -the `verify=` kwarg was silently dropped (renamed to `tls_verify=` in v0.11). The new name works: `tls_verify=False` returns 200 on the same URL.

**When a TlsOptions/Http2Options feature doesn't appear on the wire, the kwarg name is almost certainly wrong.** Do NOT conclude the feature is missing from the binary/build. Known corrections:
- ~~`ocsp_stapling`~~ → `enable_ocsp_stapling`
- ~~`cert_compression_algorithm`~~ → `certificate_compression_algorithms`
- ~~`curves`~~ → `curves_list`
- ~~`alpn_protos`~~ → `alpn_protocols`
- ~~`extensions`~~ → `extension_permutation`
- ~~`key_shares_limit`~~ (int count, pre-0.11) → `key_shares` (`Sequence[KeyShare]`, 0.11+)
- ~~`pseudo_order`~~ → `headers_pseudo_order` (Http2Options)
- SCT: `enable_signed_cert_timestamps`

**Diagnosis order when something doesn't appear on wire:**
1. **Suspect our kwarg name first** -check the Rust `TlsOptions` struct in wreq source for exact field names
2. Check `wreq-util` emulation profiles -if Chrome/Safari profiles use a feature, wreq supports it
3. Verify on the wire with `tls.peet.ws/api/all`
4. Only after all above: consider build/binary limitations

**`TlsOptions` overrides `Emulation` entirely.** Passing `tls_options=TlsOptions(...)` -even empty -destroys the Emulation profile's TLS settings. You cannot combine them.

## HTTP/2 Header Duplication

**Send a header at one level only.** Older wreq/rnet builds put a header set at both client level and per request into the HTTP/2 HEADERS frame twice, which strict WAFs (Cloudflare, DataDome) detect as non-browser behavior -> instant 403. Measured on 0.12.3 (2026-09-27, pingly echo): a per-request header replaces a same-named client header or emulation default in place, whatever its case, with no duplicate. Keep the rule anyway: it costs nothing and holds across versions.

The `_build_headers()` method returns a **delta** -only headers that are NEW or DIFFERENT from client-level. Static headers (Accept, sec-ch-ua, etc.) are set ONCE at client construction. Per-request only adds dynamic headers (Referer, Sec-Fetch-Site that follows it, embed headers, user overrides).

**Per-request `default_headers=False`** drops the emulation's default headers and the client's `headers=` for that one request, while the client's `orig_headers` still orders what is sent and the cookie jar still adds `Cookie` (wire-verified 0.12.3). It is the only way to leave out one header the emulation adds (e.g. `Sec-Fetch-User` on a script-submitted form, `wafer/_sync.py` Reddit bootstrap), so the request must carry the whole set itself.

Also: **never send Host per-request** -wreq auto-sets it from the URL. Sending it per-request duplicates the `:authority` pseudo-header.

## Emulation Enum

- **Not hashable.** Cannot use as a dict key. Use `repr(emulation)` instead (e.g. `"Profile.Chrome154"` -note: `Emulation.ChromeXXX` is a ClassVar pointing at `Profile.ChromeXXX`, so repr returns the `Profile.` form).
- **No `.name` attribute.** Use `repr()` for display and lookups.
- **A bare profile is always macOS.** `Emulation.ChromeNNN` (a `Profile`) is built with wreq-util's default `Platform.MacOS` whatever the host is, so on Linux/Windows it sent a "Macintosh" UA next to wafer's own `sec-ch-ua-platform: "Linux"`. wafer builds desktop Chrome/Edge/Firefox/Opera as `Emulation(profile=..., platform=<host>, headers=...)` (`_fingerprint.wreq_emulation`); Safari, mobile and OkHttp profiles carry their own platform and stay bare.
- **Default headers are a top-level navigation, and cannot be dropped one at a time.** A client or request header replaces a same-named default in place; nothing removes one. The only switch is `Emulation(..., headers=False)`, which drops the whole set (UA included) and leaves TLS and HTTP/2 untouched. wafer does that in embed mode and supplies every header plus the browser's order through `orig_headers` (see `docs/ref-sec-fetch.md`). A client-level `orig_headers` orders per-request headers too; a name it doesn't list is appended at the end, and it also fixes the name's case on HTTP/1.1.

## Cookie Jar

- **`Jar.get_all()` reports a host-only cookie with `domain=None`** (wreq 0.12.2+; earlier versions filled in the host that set it). A Domain cookie still reports its domain, leading dot stripped. Which host owns a host-only cookie is recoverable only through `Jar.get(name, url)` (`_base._jar_host_only_owner`).
- **`Jar.get(name, url)` looks up the URL's exact host**, with no parent-domain matching: a `Domain=example.com` cookie is not returned for `www.example.com`. A host-only cookie and a `Domain=<same host>` cookie with the same name and path share that host, and `get` returns the one created first, which is also the one the jar sends first.
- **`Jar.get(name, url)` matches the exact stored path**, not a path prefix, and does not enforce `Secure`.
- **`Max-Age` arrives as an absolute `expires`** (0.12.2+); `max_age` stays None. Read both.
- Cookies are sent longest path first, then in creation order (0.12.2+; 0.12.1 used hash order).
- `tests/conftest.py`'s `MockJar` mirrors these semantics except for path matching. Anything that depends on the jar's shape needs a test on the real `wreq.cookie.Jar` too; the mock kept the 0.12.1 shape and hid the 0.12.2 regressions until it was updated.

## Response API

- **`resp.status` is an enum**, not an int. Call `resp.status.as_int()` to get the numeric status code.
- **`resp.headers` is a `HeaderMap`**, not a dict. No `.items()` method.
  - `.keys()` returns names, `.get(key)` / `[key]` the **first** value only, `.get_all(key)` **all** values (required for multi-value headers like `Set-Cookie`).
  - Since 0.13 every name and value is a read-only `memoryview` (bytes before): no `.decode()`, and it fails `isinstance(x, bytes)`. Convert with `wafer/_bytes.py` (`as_text`, `as_bytes`, `is_binary`), never with `.decode()` or `str()`.
- **Body reading:** sync `resp.bytes()` / `resp.text()`, async `await resp.bytes()` / `await resp.text()`. `bytes()` and stream chunks are read-only `memoryview` since 0.13; `text()` and `json()` are unaffected.
- **No automatic redirect following.** wreq returns 3xx responses as-is. Wafer implements its own redirect loop with method conversion (POST->GET on 301/302/303).

## Client Construction

- Sync: `wreq.blocking.Client(**kwargs)`, async: `wreq.Client(**kwargs)`.
- **Mutually exclusive identity:** pass `emulation=` (Chrome) OR `tls_options=` + `http2_options=` (Safari). Never both.
- Cookie jar: `cookie_store=True` enables it. Access via `client.cookie_jar.add(raw_set_cookie_string, url)`.
- Proxy: `from wreq import Proxy` -> `Proxy.all(proxy_url)`, passed as `proxies=[proxy]`.
- **Client-level TLS kwargs got a `tls_` prefix in v0.11** (PR #556). Renamed: `verify` -> `tls_verify`, `verify_hostname` -> `tls_verify_hostname`, `identity` -> `tls_identity`, `keylog` -> `tls_keylog`, `min_tls_version` -> `tls_min_version`, `max_tls_version` -> `tls_max_version`. Inside `TlsOptions` itself, `min_tls_version`/`max_tls_version` are unchanged. Old names are silently ignored - see Silent Failure section.
- **v0.12 renamed `ResolverOptions` -> `DnsOptions`** (added a `system_dns: bool` first arg for the OS resolver). The `dns_options=` Client kwarg expects a `DnsOptions`; wafer uses it for the `resolve=` SSRF DNS pin (`DnsOptions().add_resolve(host, [ip_address(...)])`, see `_base._build_client_kwargs`).
- **v0.12.1 (2026-07-11) added the latest browser profiles to the Python `Emulation` enum** (feat #597, closing "Support Chrome 149"): `Chrome148`, `Chrome149`, `Edge148`, `Firefox150`, `Firefox151`, `Safari17_6`, `Safari26_3`, `Safari26_4`, `Opera131`. Newest Chrome became `Chrome149` (then `DEFAULT_EMULATION`); the cross-family ladder pins updated to `Firefox151` / `Edge148`. `repr(Emulation.Chrome149)` is still `"Profile.Chrome149"`. The 0.12.0 -> 0.12.1 diff was profiles-only (no Client/TlsOptions/Http2Options kwarg changes); Safari H2 + Dart HTTP/1.1 + `tls_verify` re-verified unchanged.
- **v0.12.2 (2026-09-16) added `Chrome150`-`Chrome153`** (#610) and moved the Rust core to pinned git revisions of wreq, wreq-util and btls. The Python API is unchanged apart from the four enum members, but the Rust move changed behavior three ways (all measured 2026-09-24):
  - **Chrome's ClientHello moves between majors.** JA4 `..._d8a2da3f94cd` through 149; 150-151 add ML-DSA signature algorithms (`..._806a8c22fdea`); 152-153 add extension 0xca34 and a GREASE signature algorithm (`t13d1517h2_8daaf6152771_cb7bf5808d99`). HTTP/2 is identical across 149-153. wreq's Chrome153 matches real Google Chrome 153.0.8010.53 exactly (JA4 and sec-ch-ua). Adjacent majors are not reliably wire-identical. (154 kept 153's JA4 and HTTP/2; see v0.13.0.)
  - **Every profile's default header set became the real browser's navigation**: Chrome/Edge/Firefox gained `sec-fetch-user: ?1` (and Chrome `upgrade-insecure-requests: 1`) in the browsers' real order. That is right for navigation and made embed="xhr" send `Sec-Fetch-Mode: cors` + `Sec-Fetch-User`, hence wafer's embed mode now owns its headers.
  - **The cookie jar's `get_all()` changed shape** (see Cookie Jar above).
  - Wheel platforms are unchanged (28 files); the musllinux build moved to GitHub runners. Default Cargo features are unchanged in effect (`webpki-roots` + `tokio-rt`, same as the 6.0.0-rc.29 that 0.12.1 built against), so the fallback root store and proxy behavior did not move.
- **v0.12.3 (2026-09-27)**: no Python API or fingerprint change (same wreq, wreq-util and btls revisions). hickory-resolver 0.26, and when the system DNS config cannot be read the resolver falls back to Cloudflare DNS instead of Google. Async request cancellation is now preserved. Re-verified on the wire (all modes, Safari, Dart, `tls_verify`, AIA, `resolve=` pin).
- **v0.13.0 (2026-10-05)** added `Chrome154` and `Firefox152` (no new Edge; `Edge148` stays the ladder's Edge). wafer pins `>=0.13.0,<0.14`. Measured 2026-10-05:
  - **Breaking type change:** `Response.bytes()`, stream chunks, `HeaderMap` keys/values/`get`/`get_all`/iteration, `peer_certificate` and WebSocket binary fields return read-only `memoryview`, not `bytes`. No kwarg was renamed or removed (the 0.12.3 -> 0.13.0 stub diff only adds `runtime=` options). The silent failures were the dangerous part: `_read_body_capped` skipped every chunk that was not `bytes` (empty bodies), and `str(memoryview)` turned a Location or Set-Cookie into `"<memory at 0x...>"`. `wafer/_bytes.py` converts at every wreq boundary, and `tests/conftest.py`'s mocks return read-only memoryviews so a regression fails a test. `RustPanic` is no longer raised for panics (wafer never caught it).
  - **Chrome154 equals real Google Chrome 154.0.8037.93 exactly**: JA4 `t13d1517h2_8daaf6152771_cb7bf5808d99` (unchanged from 153), H2 `1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p`, navigation header order and every value including `sec-ch-ua` (`"Chromium";v="154", "Google Chrome";v="154", "Not A(Brand";v="99"`).
  - **Every Firefox 150+ ClientHello changed**, `Firefox151` included (wreq-util #122): `TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA` (0xc009) is gone, so JA4 moves from `t13d1717h2_5b57614c22b0` to `t13d1617h2_86a278354501_3cbfd9057e0d`. That is the correction: real Firefox 151.0 and 153.0 (Playwright's builds, whose `playwright.cfg` sets no TLS prefs) send exactly the new value, so wafer's Firefox rung was off on 0.12.3.
  - Edge148, iOS Safari and Dart are wire-identical to 0.12.3; wafer's Safari identity is too (its UA and `zstd` vary only with the 26.2/26.3 version it picks). Embed-mode header sets and orders are unchanged; `Jar.get_all()` shape is unchanged; `tls_verify` still refuses badssl expired/self-signed; the Reddit app route (Chrome154 on Android) mints and reads.
  - The wreq-util pin (5715529) includes the UA-literal fixes from wreq-util #118.
