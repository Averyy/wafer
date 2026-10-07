# TODO: homedepot.com's Akamai challenge is not passed in fetchaller's Linux image, and the solver reports it solved

**Owner:** wafer
**Status:** PARTIAL FIX. The false positive "solved" log is fixed, and a 15s
grace window bails early when the sensor runs but the page doesn't navigate
(was burning 112s). The underlying issue is confirmed on native amd64: Akamai
refuses the browser under Xvfb regardless of architecture. Likely cause is the
software-rendered WebGL renderer (Mesa/SwiftShader).
**Reported by:** fetchaller (Docker re-test after the 0.7.2 upgrade)

---

## Symptom

The same cold read of a homedepot.com article, run minutes apart from the same
machine and network:

| where | browser | result |
|---|---|---|
| macOS (arm64), headed | branded Google Chrome 154.0.8037.99 | **200**, 5.7 s, `akamai passthrough (852703 bytes, 20 cookies)` |
| fetchaller image (linux/amd64, headed under Xvfb + jwm) | Chrome for Testing 154.0.8037.92 | **ChallengeDetected generic_js (HTTP 403)**, 16.4 s |
| same image, branded Google Chrome 155.0.8059.39 swapped in | branded Chrome 155 | same failure, 16.7 s |

URL: `https://www.homedepot.com/c/ab/how-to-use-a-drill/9ba683603be9fa5395fab9022a5fa8b`.
In the image, cookieless reads of homedepot.com still work: the federation
gateway answered 200 in 0.6 s during the same run.

## What the debug trail shows (logger `wafer` at DEBUG)

macOS: the browser reaches the real page, so the passthrough fires.

```
INFO Browser solving challenge_type=akamai
INFO akamai passthrough (852703 bytes, 20 cookies)
INFO Browser solved challenge_type=akamai (cookie_count=20)
INFO Browser passthrough challenge_type=akamai (20 cookies injected, 852703 bytes)
```

Image: the browser does **not** reach the real page. It holds 10 cookies,
there is no passthrough, and the transport replay is refused. The solve is
still reported as a success, twice:

```
INFO Browser solving challenge_type=akamai
DEBUG Browse: browse_016.csv (277 points, scale=0.87) from (438, 399)
INFO Browser solved challenge_type=akamai (cookie_count=10)
DEBUG Fingerprint pinned to browser: emulation=Profile.Chrome154 ua_version=154 (154.0.8037.92)
INFO Challenge detected: generic_js            <- replay answered 403
INFO Browser solving challenge_type=generic_js
INFO Browser solved challenge_type=generic_js (cookie_count=10)
INFO Challenge detected: generic_js
RESULT failed: ChallengeDetected generic_js ... (HTTP 403) 16.4s
```

Two things:

1. **Akamai does not pass the browser in this environment.** On macOS the same
   solve reaches the article with 20 cookies; here it stays at 10.
2. ~~**The success check accepted it anyway.**~~ **FIXED.** `wait_for_akamai`
   now requires behavioral challenges to navigate to real content before
   reporting success. An `_abck` cookie change alone is no longer enough when
   the page is a behavioral stub (`sec-if-cpt` / `behavioral-content`), because
   Akamai's sensor always updates the cookie even when the server rejects the
   fingerprint. Non-behavioral pages (normal pages with sensor alongside real
   content) still accept the `_abck` change. Test coverage in
   `tests/test_akamai_browser.py`.

## Things ruled out

- **Brand mismatch.** Chrome for Testing reports `"Not A(Brand";v="99",
  "Chromium";v="154"` (no "Google Chrome") while wafer's transport sends
  `"Chromium";v="154", "Google Chrome";v="154", "Not A(Brand";v="99"`. A real
  mismatch, but swapping in branded Google Chrome 155 fails identically, so it
  is not the cause here. It may still matter for other sites, since the image
  ships Chrome for Testing deliberately (versioned archives; Google's apt repo
  serves only the current Stable).
- **A temporary refusal from my own test volume.** Earlier, Akamai refused
  everything for ~20 minutes after a burst of cold solves (gateway HTTP 206
  "Generic errors", on macOS too). These image runs were made after it lifted:
  the gateway answered 200 in the same container, and the macOS solve passed
  in between them.

## ~~Caveat you will want to resolve first~~ RESOLVED

~~These image runs were on an Apple Silicon Mac, so the linux/amd64 image runs
under x86 emulation.~~

**Confirmed on native amd64 (2026-10-07).** Same image rebuilt with wafer
0.7.3 and Chrome 154.0.8037.92, running on native x86_64 hardware (no Rosetta).
Same failure: the sensor runs, `_abck` updates, but the page never navigates.
The solve now times out cleanly (no false "solved" log) and bails after a 15s
grace window once the sensor has run.

The cause is the Xvfb environment - most likely the software-rendered WebGL
renderer (Mesa/llvmpipe) which Akamai's sensor flags. A real GPU or GPU
passthrough to Docker would likely fix it, but that is infrastructure, not code.

## Repro

Build fetchaller's image (`docker build --platform linux/amd64 -t
fetchaller-mcp:test .` in fetchaller-mcp), then:

```python
# hd_solve_debug.py: run with
#   docker run --rm -i --platform linux/amd64 -v $PWD/hd_solve_debug.py:/tmp/s.py:ro fetchaller-mcp:test python /tmp/s.py
import asyncio, logging, os, tempfile, time
from wafer import AsyncSession
from wafer.browser import BrowserSolver

URL = "https://www.homedepot.com/c/ab/how-to-use-a-drill/9ba683603be9fa5395fab9022a5fa8b"

async def main():
    logging.basicConfig(level=logging.WARNING)
    logging.getLogger("wafer").setLevel(logging.DEBUG)
    s = AsyncSession(browser_solver=BrowserSolver(executable_path=os.environ["BROWSER_EXECUTABLE_PATH"]),
                     cache_dir=tempfile.mkdtemp())
    t = time.monotonic()
    try:
        r = await s.get(URL, timeout=120)
        print("RESULT", r.status_code, len(r.text), f"{time.monotonic() - t:.1f}s")
    except Exception as e:
        print("RESULT failed:", type(e).__name__, e)

if __name__ == "__main__":
    asyncio.run(main())
```

On macOS, run the same script with
`BROWSER_EXECUTABLE_PATH="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"`.

---

## Re-test on wafer 0.7.3 (fetchaller, 2026-10-07, same image rebuilt)

- **False positive: fixed.** In the image, all four `/c/` pages challenged and
  every solve now ends as `ChallengeDetected akamai`, no "Browser solved" line.
- **The refusal itself: unchanged.** Akamai still never passes the browser in
  the image. One container got a plain 200 with no challenge at all (0.9 s),
  which looks like Akamai's first-view grace for a new visitor, not a solve.
- **New cost: a failed solve now takes ~112 s, not ~16 s.** The solver waits
  for a navigation that never comes, then logs `Browser solve timed out after
  112.2s (challenge_type=akamai worker_continues=True)`, `Browser worker recovery
  requested (driver_interrupted=True)` and `Browser solve failed
  (challenge_type=akamai error=TargetClosedError)`. That's 115 s per request
  before the caller hears anything. Worth asking whether an Akamai behavioural
  page that hasn't moved after N seconds can be called failed sooner.
- **Failed solves look like what triggers Akamai's wider refusal.** Twice today
  a run of failed solves in the image (2, then 8) was followed within minutes
  by homedepot.com's edge refusing even the cookieless federation-gateway reads
  (HTTP 206 `{"error":[{"message":"Generic errors"}]}`, `Server: AkamaiGHost`)
  for ~20 minutes, on the Mac as well as in the image. A successful macOS solve
  followed by gateway reads did not cause it. That's correlation from two
  episodes, not proof, but it means a failing solver costs more than its own
  request. fetchaller now holds homedepot.com pages for 10 minutes after one
  failed solve, and holds the gateway after a refusal.

**UPDATE (2026-10-07):** Confirmed on native amd64: same failure. The caveat
about x86 emulation is resolved - it's the Xvfb environment, not Rosetta.
wafer 0.7.4 adds a 15s grace window so a rejected behavioral solve bails in
~15s instead of ~112s.
