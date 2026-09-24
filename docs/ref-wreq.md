# wreq Reference

Wafer wraps wreq **0.12.2+** (the `Emulation` API, formerly rnet).

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

**NEVER send the same header at both client level AND per-request level.** wreq creates duplicate entries in HTTP/2 HEADERS frames, which strict WAFs (Cloudflare, DataDome) detect as non-browser behavior -> instant 403.

The `_build_headers()` method returns a **delta** -only headers that are NEW or DIFFERENT from client-level. Static headers (Accept, sec-ch-ua, etc.) are set ONCE at client construction. Per-request only adds dynamic headers (Referer, embed headers, user overrides).

Also: **never send Host per-request** -wreq auto-sets it from the URL. Sending it per-request duplicates the `:authority` pseudo-header.

## Emulation Enum

- **Not hashable.** Cannot use as a dict key. Use `repr(emulation)` instead (e.g. `"Profile.Chrome153"` -note: `Emulation.ChromeXXX` is a ClassVar pointing at `Profile.ChromeXXX`, so repr returns the `Profile.` form).
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
  - `.keys()` returns bytes. Decode with `.decode("ascii")`.
  - `.get(key)` / `[key]` returns the **first** value only (bytes).
  - `.get_all(key)` returns **all** values -required for multi-value headers like `Set-Cookie`.
  - All values are bytes. Decode with `.decode("utf-8", errors="replace")`.
- **Body reading:** sync `resp.bytes()` / `resp.text()`, async `await resp.bytes()` / `await resp.text()`.
- **No automatic redirect following.** wreq returns 3xx responses as-is. Wafer implements its own redirect loop with method conversion (POST->GET on 301/302/303).

## Client Construction

- Sync: `wreq.blocking.Client(**kwargs)`, async: `wreq.Client(**kwargs)`.
- **Mutually exclusive identity:** pass `emulation=` (Chrome) OR `tls_options=` + `http2_options=` (Safari). Never both.
- Cookie jar: `cookie_store=True` enables it. Access via `client.cookie_jar.add(raw_set_cookie_string, url)`.
- Proxy: `from wreq import Proxy` -> `Proxy.all(proxy_url)`, passed as `proxies=[proxy]`.
- **Client-level TLS kwargs got a `tls_` prefix in v0.11** (PR #556). Renamed: `verify` -> `tls_verify`, `verify_hostname` -> `tls_verify_hostname`, `identity` -> `tls_identity`, `keylog` -> `tls_keylog`, `min_tls_version` -> `tls_min_version`, `max_tls_version` -> `tls_max_version`. Inside `TlsOptions` itself, `min_tls_version`/`max_tls_version` are unchanged. Old names are silently ignored - see Silent Failure section.
- **v0.12 renamed `ResolverOptions` -> `DnsOptions`** (added a `system_dns: bool` first arg for the OS resolver). The `dns_options=` Client kwarg expects a `DnsOptions`; wafer uses it for the `resolve=` SSRF DNS pin (`DnsOptions().add_resolve(host, [ip_address(...)])`, see `_base._build_client_kwargs`).
- **v0.12.1 (2026-07-11) added the latest browser profiles to the Python `Emulation` enum** (feat #597, closing "Support Chrome 149"): `Chrome148`, `Chrome149`, `Edge148`, `Firefox150`, `Firefox151`, `Safari17_6`, `Safari26_3`, `Safari26_4`, `Opera131`. Newest Chrome is now `Chrome149` (`DEFAULT_EMULATION`); the cross-family ladder pins updated to `Firefox151` / `Edge148`. `repr(Emulation.Chrome149)` is still `"Profile.Chrome149"`. The 0.12.0 -> 0.12.1 diff was profiles-only (no Client/TlsOptions/Http2Options kwarg changes); Safari H2 + Dart HTTP/1.1 + `tls_verify` re-verified unchanged.
- **v0.12.2 (2026-09-16) added `Chrome150`-`Chrome153`** (#610) and moved the Rust core to pinned git revisions of wreq, wreq-util and btls. The Python API is unchanged apart from the four enum members, but the Rust move changed behavior three ways (all measured 2026-09-24):
  - **Chrome's ClientHello moves between majors.** JA4 `..._d8a2da3f94cd` through 149; 150-151 add ML-DSA signature algorithms (`..._806a8c22fdea`); 152-153 add extension 0xca34 and a GREASE signature algorithm (`t13d1517h2_8daaf6152771_cb7bf5808d99`). HTTP/2 is identical across 149-153. wreq's Chrome153 matches real Google Chrome 153.0.8010.53 exactly (JA4 and sec-ch-ua). Adjacent majors are not reliably wire-identical.
  - **Every profile's default header set became the real browser's navigation**: Chrome/Edge/Firefox gained `sec-fetch-user: ?1` (and Chrome `upgrade-insecure-requests: 1`) in the browsers' real order. That is right for navigation and made embed="xhr" send `Sec-Fetch-Mode: cors` + `Sec-Fetch-User`, hence wafer's embed mode now owns its headers.
  - **The cookie jar's `get_all()` changed shape** (see Cookie Jar above).
  - Wheel platforms are unchanged (28 files); the musllinux build moved to GitHub runners. Default Cargo features are unchanged in effect (`webpki-roots` + `tokio-rt`, same as the 6.0.0-rc.29 that 0.12.1 built against), so the fallback root store and proxy behavior did not move.
