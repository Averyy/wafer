# TODO: a browser identity that persists, so a solver isn't a never-seen device

**Owner:** wafer
**Status:** PROPOSAL. Not started. Run the experiments below before any code.
It cuts against several of wafer's foundations (listed below), so the design
needs a decision first.
**Origin:** AliExpress observations from 2026-10-09; the timezone investigation
is now [closed with current measurements](docs/ref-baxia.md#priming-timezones-and-mtop-acceptance-closed-2026-10-25).
Fresh primed profiles returned product data on 2026-10-25, so the historical
rationale below is not an established requirement for persistent state.

---

## Why

AliExpress punishes a never-seen browser profile. Native macOS, same machine,
same Google Chrome binary, one factor at a time:

| Browser | Automation during load | Item page's own `pdp.pc.query` |
|---|---|---|
| the user's long-lived Chrome profile | none | passes |
| same Chrome, **fresh profile**, no debugging port | none (Chrome's own network log) | **punished** (`_____tmd_____/punish`) |
| same fresh profile, revisited 3 times over ~2 min | none | punished 3 of 3 |
| wafer's hardened Patchright Chrome, fresh context | yes | punished |

Only profile state differs: cookies, local storage, IndexedDB, cache, history.
Every wafer browser operation (solve, prime, render, intercept) runs in a brand
new context, so wafer always presents as a never-seen device. Solving works
(fetchaller, 0.7.7: every solved run read the product), but it costs a
reCAPTCHA (20-130s) on every cold session. Priming can't help, because it copies
what a fresh browser has.

This is likely not AliExpress-only. Any WAF that scores device history (Baxia,
and plausibly others that key on long-lived device cookies or storage) treats
every wafer solve as a first contact.

---

## What it goes against

- **Fresh, isolated contexts.** Each solve gets a clean context today, so one
  site's state can never leak into another solve, and a poisoned or rejected
  solve leaves nothing behind (see v0.7.6: rejected cookies kept out of
  `cache_dir`). A persistent identity carries everything forward, bad state
  included.
- **Rotation and unlinkability.** Rotation, `rotate_every` and session
  retirement deliberately drop cookies so request sequences are unlinkable. A
  long-lived device identity is the opposite: everything it does is linkable,
  which is the point here.
- **`cache_dir` is narrow and explicit.** Today it persists only solver cookies,
  as per-domain JSON (`0o600`). A browser profile persists far more, and much
  of it is opaque: local storage, IndexedDB, service workers, cache, history,
  any logins.
- **One shared `BrowserSolver`, many sessions.** A solver is shared across
  sessions and threads. A single persistent profile would mix every caller's
  sites and state into one device. Playwright's `launch_persistent_context`
  gives one context per profile, so per-solve isolation goes away.
- **Launch path and hardening.** `hardened_launch_config()` is the single source
  of launch flags, and `harden_page`, the driver preload and the headless
  patches all assume `chromium.launch` + `new_context`. A persistent context is
  a different launch path, and every leak test would need to cover it.
- **Identity coherence over time.** Transport replay pins to the solving
  browser's UA and version. A profile that outlives a Chrome update changes
  version under its own history, and a profile reused from another machine
  (fetchaller containers, volumes) changes hardware under it.
- **Deployment.** Containers need the profile on a volume. Chrome's profile lock
  (`SingletonLock`) forbids two processes on one profile. A profile can grow
  without bound.

---

## Experiments first (each decides part of the design)

1. **Does a profile stay trusted after one solve?** Use a persistent profile:
   visit, get punished, solve the reCAPTCHA in that profile (wafer's solver),
   then later revisit with plain Chrome and no automation. Repeat over hours.
   If it passes, a solve buys lasting trust and persistence is worth building.
   If not, trust comes from something a solve can't give.
2. **Which state carries the trust?** (Needs the user's OK: uses their real
   AliExpress state, copied locally and deleted after.) Seed a throwaway profile
   with only AliExpress's cookies (`cna`, `isg`, `xman_*`, `_baxia_sec_cookie_`,
   ...), then only its local storage, then both. If cookies alone carry it, the
   cheap design below works.
3. **What is the trust bound to?** With a trusted state from 1 or 2, change one
   thing at a time: a different machine (fetchaller's image), a different Chrome
   version, headless vs headed, transport replay over wreq. That decides whether
   a saved identity can move between hosts or must stay with one browser.
4. **Breadth.** Check whether other WAFs in `docs/site-list.md` behave
   differently for a fresh vs a returning profile (DataDome, PX, Kasada,
   Akamai). One known case doesn't justify a framework.

---

## Design options (least invasive first)

**A. Per-site saved browser state in `cache_dir`, opt-in (preferred if
experiment 2 says cookies + local storage suffice).**
- After a validated solve, save Playwright `storage_state` (cookies + local
  storage, optionally IndexedDB) for that registrable domain only, next to the
  existing cookie JSON (`0o600`). The next solve for that site starts its fresh
  context seeded with that site's state.
- Keeps per-solve contexts, per-site isolation, `cache_dir` semantics, rejection
  rules (only validated clearance is saved, as with cookies since v0.7.6) and
  the existing launch path. Retirement and rotation clear it with the site's
  cookies.
- Opt-in, e.g. `AsyncSession(..., browser_state="per_site")` or a
  `BrowserSolver` flag. The default stays fresh and unlinkable.

**B. A persistent profile directory, opt-in.**
- `BrowserSolver(profile_dir=...)` via `launch_persistent_context`: the whole
  profile (cache, history, service workers) persists. This is closest to a
  personal browser.
- One profile per solver instance; cross-process use refused (profile lock).
  Callers who want isolation make one solver per identity.
- Biggest blast radius: new launch path, all hardening and leak tests duplicated,
  everything linkable, opaque state. Only if A is shown not to be enough.

**C. Warm-up only (no persistence):** visit the origin in the same context
first. Already ruled out for AliExpress: a fresh profile is punished on the
first page view, and three revisits didn't change it.

---

## Acceptance (whichever design)

- A live A/B on AliExpress MTop: fresh (today) vs saved state, interleaved, on
  native macOS and in fetchaller's Linux image. Show the captcha rate dropping,
  with the solve-every-time path still working when the saved state is rejected.
- Rejected or expired state is dropped, never replayed (same rule as cookies).
- Off by default; `llms.txt` documents the linkability trade-off plainly.
- `tests/test_headless_leaks.py` still passes on whatever launch path ships.

## Until then

Validate the signed application response after priming. If it is challenged,
solve the issued URL and retry within the caller's deadline. `llms.txt` and
`docs/ref-baxia.md` now document the distinction between imported browser state
and accepted MTop responses; neither a fresh profile nor its timezone alone
determines the outcome.
