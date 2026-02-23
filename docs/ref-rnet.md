# rnet Reference

Wafer wraps rnet **3.0.0rc21+** (the `Emulation` API). NOT the stable 2.x series (which uses the old `Impersonate` API).

## TlsOptions Silent Failure

**`TlsOptions(**kwargs)` silently accepts ANY kwargs — including typos and wrong names.** There is no validation, no `.pyi` stub, and no error. A kwarg being "accepted" means nothing. Only wire verification proves it works.

**When a TlsOptions feature doesn't appear on the wire, the kwarg name is almost certainly wrong.** Do NOT conclude the feature is missing from the binary/build. Known corrections:
- ~~`ocsp_stapling`~~ → `enable_ocsp_stapling`
- ~~`cert_compression_algorithm`~~ → `certificate_compression_algorithms`
- ~~`curves`~~ → `curves_list`
- SCT: `enable_signed_cert_timestamps`

**Diagnosis order when something doesn't appear on wire:**
1. **Suspect our kwarg name first** — check the Rust `TlsOptions` struct in rnet/wreq source for exact field names
2. Check `wreq-util` emulation profiles — if Chrome/Safari profiles use a feature, rnet supports it
3. Verify on the wire with `tls.peet.ws/api/all`
4. Only after all above: consider build/binary limitations

**`TlsOptions` overrides `Emulation` entirely.** Passing `tls_options=TlsOptions(...)` — even empty — destroys the Emulation profile's TLS settings. You cannot combine them.

## HTTP/2 Header Duplication

**NEVER send the same header at both client level AND per-request level.** rnet creates duplicate entries in HTTP/2 HEADERS frames, which strict WAFs (Cloudflare, DataDome) detect as non-browser behavior → instant 403.

The `_build_headers()` method returns a **delta** — only headers that are NEW or DIFFERENT from client-level. Static headers (Accept, sec-ch-ua, etc.) are set ONCE at client construction. Per-request only adds dynamic headers (Referer, embed headers, user overrides).

Also: **never send Host per-request** — rnet auto-sets it from the URL. Sending it per-request duplicates the `:authority` pseudo-header.

## Emulation Enum

- **Not hashable.** Cannot use as a dict key. Use `repr(emulation)` instead (e.g. `"Emulation.Chrome145"`).
- **No `.name` attribute.** Use `repr()` for display and lookups.
- **macOS User-Agent.** Chrome Emulation profiles produce a macOS User-Agent when running on macOS hosts. This is correct browser behavior — real Chrome does the same.

## Response API

- **`resp.status` is an enum**, not an int. Call `resp.status.as_int()` to get the numeric status code.
- **`resp.headers` is a `HeaderMap`**, not a dict. No `.items()` method.
  - `.keys()` returns bytes. Decode with `.decode("ascii")`.
  - `.get(key)` / `[key]` returns the **first** value only (bytes).
  - `.get_all(key)` returns **all** values — required for multi-value headers like `Set-Cookie`.
  - All values are bytes. Decode with `.decode("utf-8", errors="replace")`.
- **Body reading:** sync `resp.bytes()` / `resp.text()`, async `await resp.bytes()` / `await resp.text()`.
- **No automatic redirect following.** rnet returns 3xx responses as-is. Wafer implements its own redirect loop with method conversion (POST→GET on 301/302/303).

## Client Construction

- Sync: `rnet.blocking.Client(**kwargs)`, async: `rnet.Client(**kwargs)`.
- **Mutually exclusive identity:** pass `emulation=` (Chrome) OR `tls_options=` + `http2_options=` (Safari). Never both.
- Cookie jar: `cookie_store=True` enables it. Access via `client.cookie_jar.add(raw_set_cookie_string, url)`.
- Proxy: `from rnet import Proxy` → `Proxy.all(proxy_url)`, passed as `proxies=[proxy]`.
