# Kasada Solver

## Status

**Detection**: Done. Header-based (`x-kpsdk-*` on 429) and body-based (`ips.js`, `kpsdk`, `/p.js` markers).

**Browser solve (CT+ST extraction)**: Done. Patchright navigates to protected URL, response listener intercepts `x-kpsdk-ct` and `x-kpsdk-st` from ips.js/p.js/tl responses. 10-second post-CT settle time ensures cookies are fully set.

**CD generation (per-request PoW)**: Done. Pure Python SHA-256 with hash chaining (`wafer/_kasada.py`). Generates fresh `x-kpsdk-cd` per request in ~1ms. Algorithm matches Fweak gist / tramodule spec (initial hash from challenge_id, sequential nonces, hash chaining between subchallenges).

**Integration**: Done. Session cache with 30-min TTL, cookie-based auth for simple deployments. Passthrough mode for dual-WAF sites (browser captures post-solve page content when cookie replay fails due to TLS-bound tokens). CT+CD header injection disabled pending x-kpsdk-h HMAC generation.

**Signed APIs (in-page replay)**: Done (2026-11-03). A deployment that signs each API call refuses an unsigned one with a bare 403/429 in the API's own content type, and the browser makes the call instead, through the SDK's fetch hook. See "Signed API calls" below.

**Validated against real sites**:
- `realestate.com.au` -server-side 429, browser-solve PASS, cookie auth 5/5 durability (Feb 2026)
- `hyatt.com` -server-side 429 (also Akamai CDN), browser-solve PASS, cookie auth 5/5, 43 cookies (Feb 2026)
- `chewy.com` -dual-WAF (Akamai + Kasada), browser-solve PASS, passthrough 2.0MB. Full CT+CD+ST flow (ST returned from /tl). Cookie replay fails (_abck TLS-bound), uses passthrough. Requires `--force-color-profile=scrgb-linear` + skipping `_HEADLESS_FIX_SCRIPT` (ips.js detects Function.prototype.toString wrapper). (Mar 2026)

**Skipped items** (resolved or not worth pursuing):
- CDP console detection mitigation -resolved by Patchright (removes `Runtime.enable` + `Console.enable`) and Chrome V8 engine patch (Chrome 137+, May 2025). Solver works without any mitigation code.
- Full VM reimplementation -not justified. Browser-for-CT + Python-CD architecture is excellent. VM engine is achievable but browser API mocks (~460 LOC) require ongoing monthly maintenance as Kasada adds fingerprint checks. No public working implementation exists.

## ST/CD Flow Validation

**CD algorithm rewritten (Mar 2026)** to match the Fweak gist / tramodule Kasada-Solver spec exactly: initial hash from random challenge_id, sequential nonces starting from 1, hash chaining between subchallenges, correct output format (`workTime`, `id`, `answers`, `duration`, `d`, `st`, `rst`). The previous implementation used a different (incorrect) algorithm with random large nonces and no hash chaining.

Unit-tested (`tests/test_kasada.py::TestGenerateCD`) with hash chain replay verification.

### 2026-02-23 Investigation: Twitch Integrity

**`gql.twitch.tv/integrity`** uses the full Kasada CT+CD flow:

1. Kasada `p.js` is hosted at `k.twitchcdn.net` (CDN-specific Kasada script URL)
2. The script opens a hidden iframe to `gql.twitch.tv/{uuid1}/{uuid2}/fp?x-kpsdk-v=j-0.0.0`
3. ips.js VM runs fingerprinting + challenge solving inside the iframe
4. VM POSTs to the `/tl` endpoint → response returns **both `x-kpsdk-ct` AND `x-kpsdk-st`**
5. The patched `window.fetch` injects CT+CD headers on the actual POST to `/integrity`

This is confirmed by multiple commercial Kasada solver APIs (EzCaptcha, Hyper Solutions, MeshPrivacy) which all document the Twitch flow as requiring `x-kpsdk-cd` generated from the `x-kpsdk-st` value.

**Key difference from realestate.com.au/hyatt.com**: Twitch is an API-style Kasada deployment (POST to `/integrity`, not a page-navigate flow). The Kasada script patches `window.fetch` to automatically inject headers.

**Status**: Steps 1-2 are done - `setup_kasada_listener` captures both CT and ST, and `generate_cd(st)` produces valid CD tokens. The remaining blocker is **x-kpsdk-h** (HMAC binding CT to CD) - without H, sending CT+CD causes server rejection. H generation requires reverse-engineering the HMAC key derivation from ips.js VM state.

**Other candidates**:
- `draftkings.com` -2026-02-21: TLS passes Cloudflare on homepage. Kasada presence unverified on deeper pages.
- Any Kasada site that rejects cookie-only auth with a 429

## Signed API calls

Some deployments sign every call to a protected API rather than a page load. The SDK (`p.js`) wraps the page's `fetch`/`XMLHttpRequest` and adds `x-kpsdk-ct`, `x-kpsdk-cd`, `x-kpsdk-h` and `x-kpsdk-v` to each request to an endpoint its `KPSDK.configure([...])` list names. The server refuses a call without them, cookies or not.

**Measured on `gdx-api.costco.com/catalog/search/api/v1/search` (2026-11-03):**

| Request | Result |
|---|---|
| wreq POST, no cookies | 429, empty body, `text/plain;charset=UTF-8`, `x-kpsdk-ct` + `x-kpsdk-r: 1-AA` |
| wreq POST with every cookie a browser page load earned (`KP_UIDz`, `KP_UIDz-ssn`, ...) | 429, same |
| The page's own search POST (`www.costco.com/s?keyword=laptop`) | 200, carries all four `x-kpsdk-*` |
| `fetch()` evaluated in the page's **main world**, `credentials: 'same-origin'` (the site's own mode) | 200, 166KB JSON, all four headers added by the SDK |
| Same, `credentials: 'include'` | `TypeError: Failed to fetch` (the API's CORS does not allow credentials) |
| `fetch()` in Patchright's **isolated world** | not signed (the isolated world's `fetch` is the native one) |

So the per-request `x-kpsdk-h` (an HMAC over SDK state wafer cannot reproduce) is the whole gate: CT alone, cookies alone, or CT + a Python CD do not pass.

**What wafer does.** A 403/429 carrying `x-kpsdk-*` headers is classified `kasada` whatever its Content-Type (`is_kasada_api_refusal`; JSON/text responses are otherwise exempt from detection, but no origin API sends those headers). When the refused request is not a plain HTML navigation (it is not a GET, or the refusal is not HTML), the browser solve navigates the page the call comes from instead of the API URL: the caller's `Referer`, else its `Origin`, else the session's `embed_origin`; `solve_origin` overrides all three. It waits for `KPSDK.isReady()` and issues the caller's request (method, body, content type, and the caller's own headers less the ones a page may not set) from the main world through CDP `Runtime.evaluate`, so the SDK's hook signs it. The response comes back as a passthrough. It earns nothing reusable, since each signature is single-use, so every refused call goes through the browser again (about 4-6s each on costco.com, page load included). A request that names no page to come from keeps the old solve on its own URL, and so does a `multipart=` request: wreq's multipart object cannot be read back, and remade without its upload the call could hand back the API's answer to an empty request (the Imperva XHR replay skips it for the same reason). The fetch gets one deadline for both its attempts (credentialed, then same-origin when CORS refuses credentials). It follows redirects itself, and fetch cannot be told how many, so the hops are counted from the page's requests (`redirected_from` chains) and checked against what the session's `max_redirects` still allows; past it, or on any redirect with none left, it raises `TooManyRedirects` as the session's own loop does.

**The signing browser is scored.** In fetchaller's Linux image (Chrome for Testing 154, Xvfb, emulated amd64, Canadian IP) the page's own search POST was signed with all four headers and still answered 429 while the browser's clock was UTC, on wafer 0.7.11 and on this change alike (0 of 2). Every named zone tried passed from the same IP: America/Toronto 2 of 2, America/Vancouver, Europe/London (UTC's own offset in November) and Asia/Tokyo 1 of 1 each, both calls per run 200. So Kasada refuses the UTC zone itself, which is what servers, containers and fingerprint-resisting browsers report, not a mismatch between the clock and the IP's region. A browser that would inherit UTC (no `timezone=`, no `TZ`, system clock UTC) is therefore launched on Europe/London (`_INHERITED_UTC_ZONE` in `wafer/browser/_solver.py`), logged once at INFO; an explicit `TZ=UTC` is kept and warned about. In the image the signed call took about 24-28s, mostly page load, so the 30s default timeout was not enough.

**No page cookies come back.** The signed call's result carries none of the page's cookies. The site's own page calls `gdx-api` and `ecom-api` cross-origin with no cookies (captured by fetchaller on a real page load), so they played no part in the response. Handing them back put costco.com's consent cookie `tcm` (`Domain=.costco.com`, expiring 2027) into the session's jar and `cache_dir`, and `ecom-api.costco.com` answers any request carrying it with a bare 403: one signed search broke every later location read, in that session and any sharing the cache. Measured after the fix in the image (no `TZ`, so London): locator 200, signed search 200 with 0 cookies injected, locator again 200, a fresh session on the same `cache_dir` 200.

## Headless Detection

Kasada's ips.js detects headless Chrome via two independent mechanisms:

### 1. CSS computed style cross-check (rendering pipeline)

ips.js creates DOM elements with `@media (color: 10)` CSS rules and reads `getComputedStyle()`. On headed macOS Chrome, the Display P3 pipeline reports 10-bit color. Headless Chrome defaults to 8-bit sRGB. This cannot be faked via JS or CDP `Emulation.setEmulatedMedia` - the CSS query result comes from the actual rendering pipeline.

**Fix:** `--force-color-profile=scrgb-linear` launch flag makes the rendering pipeline report 10-bit color, matching headed Chrome. All three CSS signals now match:

| Signal | Headed | Headless (default) | Headless (scrgb-linear) |
|---|---|---|---|
| `@media (color: 10)` | true | false | true |
| `@media (color: 8)` | false | true | false |
| `@media (dynamic-range: high)` | true | false | true |

### 2. Function.prototype.toString wrapper detection

ips.js detects the `Function.prototype.toString` override used by `_HEADLESS_FIX_SCRIPT` to make patched getters appear native. The exact detection mechanism is unknown (possibly checks for closure references, Map backing, or toString identity).

**Fix:** Skip `_HEADLESS_FIX_SCRIPT` entirely for Kasada challenges. The scrgb-linear flag handles the CSS signals, and Kasada accepts `colorDepth=24` when the rendering pipeline reports 10-bit color. The getter patches for `outerWidth`/`outerHeight`/`screenY` are only needed for DataDome, not Kasada.

## How Kasada Works

### Token Model

Kasada uses three tokens. The critical insight is that CT and CD are **completely separable** -CT requires a browser, CD does not.

| Token | What It Contains | How Often | Browser Required? |
|-------|-----------------|-----------|-------------------|
| `x-kpsdk-ct` | Client fingerprint + challenge solution | Once per session (~30 min TTL, reusable) | **Yes** |
| `x-kpsdk-cd` | Proof-of-work answers + timestamp + ID | **Fresh per request** (single-use) | **No** |
| `x-kpsdk-h` | HMAC binding CT to CD | Per request | No |
| `x-kpsdk-st` | Server timestamp | Returned from `/tl` endpoint | No |

### Challenge Flow

```
1. GET /protected-page
   ← 429 + x-kpsdk-ct header + HTML referencing p.js

2. GET /fp?x-kpsdk-v=j-xxx
   ← 429 + HTML with ips.js reference

3. GET /ips.js?tkrm_alpekz_s1.3=...
   ← ~386K chars of obfuscated JavaScript (custom VM bytecode)

4. [ips.js executes: fingerprints browser, solves initial challenge]
   POST /tl (application/octet-stream)
   ← 200 + x-kpsdk-ct + x-kpsdk-st + cookies (tkrm_alpekz_s1.3, 24h Max-Age)

5. [For each subsequent request]
   GET /protected-page
   Headers: x-kpsdk-ct=<cached>, x-kpsdk-cd=<fresh PoW>, x-kpsdk-h=<HMAC>
   ← 200 (success)
```

### Per-Request Proof-of-Work (CD)

**CD generation is pure SHA-256. No VM, no bytecode, no browser.** The algorithm has been fully extracted (kasada_cryptoPow.js gist by Fweak, Feb 2024; tramodule/Kasada-Solver).

#### Algorithm

```python
import hashlib

def _hash_difficulty(h: str) -> float:
    return 0x10000000000000 / (int(h[:13], 16) + 1)

def generate_cd(st: int, difficulty: int = 10, subchallenges: int = 2) -> dict:
    challenge_id = random.randbytes(16).hex()
    hash_val = hashlib.sha256(
        f"tp-v2-input, {st}, {challenge_id}".encode()
    ).hexdigest()
    answers = []
    for _ in range(subchallenges):
        nonce = 1
        while True:
            h = hashlib.sha256(f"{nonce}, {hash_val}".encode()).hexdigest()
            if _hash_difficulty(h) >= difficulty / subchallenges:
                answers.append(nonce)
                hash_val = h
                break
            nonce += 1
    d = random.randint(1400, 2700)
    return {
        "workTime": int(time.time() * 1000) - d,
        "id": challenge_id,
        "answers": answers,
        "duration": round(random.uniform(2.0, 8.0), 1),
        "d": d, "st": st, "rst": st + d,
    }
```

#### CD Token Structure

```json
{
  "workTime": 1707645962556,
  "id": "e4369e98db038a24585a4e76a3fdcb1d",
  "answers": [13, 1],
  "duration": 3.4,
  "d": 3388,
  "st": 1707644948142,
  "rst": 1707644951530
}
```

- `workTime` = `Date.now() - d` (simulated network delay)
- `id` = random 32-char hex string
- `answers` = nonces satisfying hash difficulty (small integers, typically 1-50)
- `duration` = random plausible computation time (seconds)
- `d` = random offset 1400-2700ms (simulated server round-trip)
- `st` = `x-kpsdk-st` timestamp from `/tl` response
- `rst` = `st + d`

#### Key Parameters

- `"tp-v2-input"` -platform input identifier (stable across observed deployments)
- `difficulty` = 10 (typical), `subchallenges` = 2 (typical)
- Per-nonce: `2^52 / (parseInt(hash[0:13], 16) + 1) >= difficulty / subchallenges`

**Stability**: The CD PoW algorithm was publicly extracted in Feb 2024 (Fweak gist) and remains unchanged as of Feb 2026. The `"tp-v2-input"` string, SHA-256 hash grinding, and difficulty parameters are a **protocol** -changing them would require coordinated rollout across all Kasada customer deployments and break every cached p.js in browsers. This is fundamentally different from the VM bytecode (which rotates per-load) -the PoW wire format is stable infrastructure.

**Caveat**: Hyper Solutions Go SDK recently added a `Script` field to `KasadaPowInput`, suggesting some sites may derive difficulty or platform input from the ips.js script itself. If so, it's still trivial to regex out the parameters without running the VM.

#### CD Inputs (Minimal)

Only needs:
- `st` -the `x-kpsdk-st` value from `/tl` response

Does NOT need:
- ~~`ct`~~ -not used in CD computation
- ~~`script`~~ -not needed for standard PoW (may be needed for parameter extraction on some sites)
- ~~`domain`~~ -not used in the hash
- ~~Browser APIs~~ -zero DOM/canvas/WebGL involvement

## Test Sites

| Site | Status | Notes |
|------|--------|-------|
| `chewy.com` | **Validated** | 2026-03-03: dual-WAF (Akamai+Kasada), browser-solve PASS headless, passthrough 2.0MB, 36 cookies. Requires scrgb-linear color profile + no getter patches (ips.js detects Function.prototype.toString wrapper). Cookie replay fails (_abck TLS-bound). |
| `realestate.com.au` | **Validated** | 2026-02-21: server-side 429, browser-solve PASS, cookie auth 5/5, no ST |
| `hyatt.com` | **Validated** | 2026-02-21: server-side 429, browser-solve PASS, cookie auth 5/5, 43 cookies, no ST |
| `scheels.com` | tls-pass | 2026-02-21: Chrome145 TLS passes. Cloudflare CDN blocks naked. Kasada client-side only. |
| `vividseats.com` | tls-pass | 2026-02-21: 200 even with naked client. No server-side enforcement. |
| `footlocker.co.uk` | tls-pass | 2026-02-21: 200 even with naked client. Kasada SDK present but no enforcement. |
| `wizzair.com` | tls-pass | 2026-02-21: no Kasada markers found. |
| `gql.twitch.tv/integrity` | untested | API-style Kasada (POST). Returns x-kpsdk-ct directly. May have ST. |
| `gdx-api.costco.com` (search POST) | **Validated** | 2026-11-03: signed API (CT+CD+H+V per call). Unsigned POST and cookie-only replay 429; in-page signed replay from the caller's Referer page 200 JSON, 4 of 4, 4-6s each. |
| `draftkings.com` | unverified | Aggressive behavioral scoring. May use full CT+CD enforcement. |
| `bet365.com` | unverified | Kasada + in-house (hardest known deployment). |

## References

### Open Source Tools

| Project | Stars | What It Does |
|---------|-------|-------------|
| [kpsdk-solver](https://github.com/0x6a69616e/kpsdk-solver) | 72 | Playwright-based solver. Intercepts SDK messages, manipulates Fetch API. Firefox recommended. Archived but functional. |
| [ips-disassembler](https://github.com/umasii/ips-disassembler) | 56 | Node.js tool that disassembles ips.js VM bytecode into human-readable opcodes. Research tool. |
| [Kasada-Deobfuscated](https://github.com/Humphryyy/Kasada-Deobfuscated) | 23 | Partial deobfuscation of p.js outer layer. VM logic still intact. |
| [kasada-dissembler](https://github.com/jtwmyd/kasada-dissembler) | 5 | Modified VM interpreter that traces every opcode with labels. Runs in browser console. |
| [Kasada-Reverse-new](https://github.com/chenpython/Kasada-Reverse-new) | -| Python scripts for dynamic VM dumping (`VM.py`) and TEA encryption extraction (`encryption.py`). |
| [Kasada-Solver](https://github.com/tramodule/Kasada-Solver) | -| Token lifecycle documentation. Describes CT/CD/H token model and three-layer defense architecture. |
| [kasada_cryptoPow.js](https://gist.github.com/Fweak/d101137cd4b909b9694457a7b1debb7c) | gist | **Fully extracted CD PoW algorithm.** SHA-256 hash grinding with `tp-v2-input` platform string. The key breakthrough that makes pure-Python CD generation possible. |

### Research

- [nullpt.rs "Devirtualizing Nike.com's Bot Protection"](https://nullpt.rs/devirtualizing-nike-vm-1) (umasi, Jan 2023) -Definitive reverse-engineering of ips.js VM: bytecode decoding, opcode identification, string table extraction. [Part 2](https://nullpt.rs/devirtualizing-nike-vm-2): TEA encryption, full disassembly
- [nullpt.rs "Reversing Vercel's BotID"](https://nullpt.rs/reversing-botid) (veritas, Jun 2025) -Confirms Kasada VM architecture unchanged through mid-2025
- [kasada_cryptoPow.js gist](https://gist.github.com/Fweak/d101137cd4b909b9694457a7b1debb7c) (Fweak, Feb 2024) -**Fully extracted CD PoW algorithm**: SHA-256 hash grinding, `tp-v2-input` platform string, difficulty/subchallenges parameters
- Commercial solvers (Hyper Solutions, antibot.to, Solverly, MeshPrivacy) accept script content as input -confirming dynamic interpretation is required for CT, not hardcoded logic

### Commercial APIs (fallback)

Hyper Solutions, antibot.to, Solverly, nocaptcha -all accept script content as input, confirming dynamic interpretation needed for CT. CD is single-use, CT is reusable.
