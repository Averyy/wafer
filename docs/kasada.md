# Kasada Solver

## Status

**Detection**: Done. Header-based (`x-kpsdk-*` on 429) and body-based (`ips.js`, `kpsdk`, `/p.js` markers).

**Browser solve (CT extraction)**: Done. Patchright navigates to protected URL, response listener intercepts `x-kpsdk-ct` from ips.js/p.js response. 10-second post-CT settle time ensures cookies are fully set.

**CD generation (per-request PoW)**: Done. Pure Python SHA-256 (~30 LOC in `wafer/_kasada.py`). Generates fresh `x-kpsdk-cd` per request in ~1ms.

**Integration**: Done. Session cache with 30-min TTL, CT+CD header injection in `_build_headers()`, cookie-only fallback when ST=0.

**Validated against real sites (Feb 2026)**:
- `realestate.com.au` — server-side 429, browser-solve PASS, cookie auth 5/5 durability
- `hyatt.com` — server-side 429 (also Akamai CDN), browser-solve PASS, cookie auth 5/5, 43 cookies

**Skipped items** (resolved or not worth pursuing):
- CDP console detection mitigation — resolved by Patchright (removes `Runtime.enable` + `Console.enable`) and Chrome V8 engine patch (Chrome 137+, May 2025). Solver works without any mitigation code.
- Full VM reimplementation — not justified. Browser-for-CT + Python-CD architecture is excellent. VM engine is achievable but browser API mocks (~460 LOC) require ongoing monthly maintenance as Kasada adds fingerprint checks. No public working implementation exists.

## Open: ST/CD Flow Validation

**The CT+CD per-request header injection path has never been validated against a real Kasada deployment.** Both confirmed server-side sites (realestate.com.au, hyatt.com) return CT but no ST from ips.js. Without ST, `generate_cd()` is never called and only cookie-based auth is used.

The CD code is unit-tested (`tests/test_kasada.py::TestGenerateCD`) and the algorithm matches the public spec (Fweak gist, Feb 2024), but end-to-end proof against a real WAF is missing.

**What we need**: A Kasada deployment that returns `x-kpsdk-st` and enforces CT+CD headers per-request. Candidates:
- `gql.twitch.tv/integrity` — API-style Kasada (POST, returns x-kpsdk-ct directly). Structurally different from page-navigate flow; may need a different interception strategy.
- `draftkings.com` — aggressive behavioral scoring, may use full CT+CD enforcement
- Any new Kasada site that rejects cookie-only auth with a 429

**When found**: test the full flow (browser solve → CT+ST cached → subsequent requests carry CT + fresh CD → 200). If CD is rejected, compare our output against the reference algorithm and debug.

## How Kasada Works

### Token Model

Kasada uses three tokens. The critical insight is that CT and CD are **completely separable** — CT requires a browser, CD does not.

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

- `"tp-v2-input"` — platform input identifier (stable across observed deployments)
- `difficulty` = 10 (typical), `subchallenges` = 2 (typical)
- Per-nonce: `2^52 / (parseInt(hash[0:13], 16) + 1) >= difficulty / subchallenges`

**Stability**: The CD PoW algorithm was publicly extracted in Feb 2024 (Fweak gist) and remains unchanged as of Feb 2026. The `"tp-v2-input"` string, SHA-256 hash grinding, and difficulty parameters are a **protocol** — changing them would require coordinated rollout across all Kasada customer deployments and break every cached p.js in browsers. This is fundamentally different from the VM bytecode (which rotates per-load) — the PoW wire format is stable infrastructure.

**Caveat**: Hyper Solutions Go SDK recently added a `Script` field to `KasadaPowInput`, suggesting some sites may derive difficulty or platform input from the ips.js script itself. If so, it's still trivial to regex out the parameters without running the VM.

#### CD Inputs (Minimal)

Only needs:
- `st` — the `x-kpsdk-st` value from `/tl` response

Does NOT need:
- ~~`ct`~~ — not used in CD computation
- ~~`script`~~ — not needed for standard PoW (may be needed for parameter extraction on some sites)
- ~~`domain`~~ — not used in the hash
- ~~Browser APIs~~ — zero DOM/canvas/WebGL involvement

## Test Sites

| Site | Status | Notes |
|------|--------|-------|
| `realestate.com.au` | **Validated** | 2026-02-21: server-side 429, browser-solve PASS, cookie auth 5/5, no ST |
| `hyatt.com` | **Validated** | 2026-02-21: server-side 429, browser-solve PASS, cookie auth 5/5, 43 cookies, no ST |
| `scheels.com` | tls-pass | 2026-02-21: Chrome145 TLS passes. Cloudflare CDN blocks naked. Kasada client-side only. |
| `vividseats.com` | tls-pass | 2026-02-21: 200 even with naked client. No server-side enforcement. |
| `footlocker.co.uk` | tls-pass | 2026-02-21: 200 even with naked client. Kasada SDK present but no enforcement. |
| `wizzair.com` | tls-pass | 2026-02-21: no Kasada markers found. |
| `gql.twitch.tv/integrity` | untested | API-style Kasada (POST). Returns x-kpsdk-ct directly. May have ST. |
| `draftkings.com` | unverified | Aggressive behavioral scoring. May use full CT+CD enforcement. |
| `bet365.com` | unverified | Kasada + in-house (hardest known deployment). |

Previously listed but **not Kasada** (verified Feb 2026):
- `canadagoose.com` — DOSarrest (status 463), not Kasada
- `hyatt.com` was originally listed as "Akamai only" — actually has both Akamai CDN + Kasada server-side

## References

### Open Source Tools

| Project | Stars | What It Does |
|---------|-------|-------------|
| [kpsdk-solver](https://github.com/0x6a69616e/kpsdk-solver) | 72 | Playwright-based solver. Intercepts SDK messages, manipulates Fetch API. Firefox recommended. Archived but functional. |
| [ips-disassembler](https://github.com/umasii/ips-disassembler) | 56 | Node.js tool that disassembles ips.js VM bytecode into human-readable opcodes. Research tool. |
| [Kasada-Deobfuscated](https://github.com/Humphryyy/Kasada-Deobfuscated) | 23 | Partial deobfuscation of p.js outer layer. VM logic still intact. |
| [kasada-dissembler](https://github.com/jtwmyd/kasada-dissembler) | 5 | Modified VM interpreter that traces every opcode with labels. Runs in browser console. |
| [Kasada-Reverse-new](https://github.com/chenpython/Kasada-Reverse-new) | — | Python scripts for dynamic VM dumping (`VM.py`) and TEA encryption extraction (`encryption.py`). |
| [Kasada-Solver](https://github.com/tramodule/Kasada-Solver) | — | Token lifecycle documentation. Describes CT/CD/H token model and three-layer defense architecture. |
| [kasada_cryptoPow.js](https://gist.github.com/Fweak/d101137cd4b909b9694457a7b1debb7c) | gist | **Fully extracted CD PoW algorithm.** SHA-256 hash grinding with `tp-v2-input` platform string. The key breakthrough that makes pure-Python CD generation possible. |

### Research

- [nullpt.rs "Devirtualizing Nike.com's Bot Protection"](https://nullpt.rs/devirtualizing-nike-vm-1) (umasi, Jan 2023) — Definitive reverse-engineering of ips.js VM: bytecode decoding, opcode identification, string table extraction. [Part 2](https://nullpt.rs/devirtualizing-nike-vm-2): TEA encryption, full disassembly
- [nullpt.rs "Reversing Vercel's BotID"](https://nullpt.rs/reversing-botid) (veritas, Jun 2025) — Confirms Kasada VM architecture unchanged through mid-2025
- [kasada_cryptoPow.js gist](https://gist.github.com/Fweak/d101137cd4b909b9694457a7b1debb7c) (Fweak, Feb 2024) — **Fully extracted CD PoW algorithm**: SHA-256 hash grinding, `tp-v2-input` platform string, difficulty/subchallenges parameters
- Commercial solvers (Hyper Solutions, antibot.to, Solverly, MeshPrivacy) accept script content as input — confirming dynamic interpretation is required for CT, not hardcoded logic

### Commercial APIs (for reference/fallback)

| Service | Approach | Notes |
|---------|----------|-------|
| Hyper Solutions (`hyper-sdk-py`) | Server-side CT + CD generation | Python/JS/Go SDKs. Accepts script content as input. |
| antibot.to | API for CT + CD | CD response: `{workTime, id, answers, duration}` |
| Solverly | API for both phases | Similar to Hyper |
| nocaptcha (chrisyp.github.io) | "Pure calculation mode" for CD | Confirms CT reusable, CD single-use |
