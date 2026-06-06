# wreq Reference

Wafer wraps wreq **0.12.0+** (the `Emulation` API, formerly rnet).

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

- **Not hashable.** Cannot use as a dict key. Use `repr(emulation)` instead (e.g. `"Profile.Chrome147"` — note: `Emulation.ChromeXXX` is a ClassVar pointing at `Profile.ChromeXXX`, so repr returns the `Profile.` form).
- **No `.name` attribute.** Use `repr()` for display and lookups.
- **macOS User-Agent.** Chrome Emulation profiles produce a macOS User-Agent when running on macOS hosts. This is correct browser behavior -real Chrome does the same.

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
- **v0.12 renamed `ResolverOptions` -> `DnsOptions`** (added a `system_dns: bool` first arg for the OS resolver). Wafer does not use it, but the `dns_options=` Client kwarg now expects a `DnsOptions`. v0.12 also tracks Chrome/Edge 148 + Safari 26.2/26.4 at the Rust (`wreq-util`) level, but the Python `Emulation` enum still tops out at `Chrome147` -do not assume `Emulation.Chrome148` exists.
