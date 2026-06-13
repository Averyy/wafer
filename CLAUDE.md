# Wafer

Anti-detection HTTP client for Python. Wraps wreq with opinionated defaults for TLS fingerprinting, challenge detection/solving, cookie caching, retry, and rate limiting.

## Web Fetching and Web Searching

**For testing wafer functionality**: ALWAYS use wafer itself (`uv run python -c "import wafer; ..."` or test scripts). Never use fetchaller to test links, WAF challenges, solver behavior, or anything wafer is supposed to handle -that defeats the purpose.

## Debugging Rules

**NEVER blame IP blocks, rate limits, or network-level bans for failures.** If a site works in a normal browser, it must work in wafer. "IP is flagged" is not a valid excuse -the whole point of wafer is to be indistinguishable from a real browser. If a WAF blocks wafer but not a browser, the bug is in wafer's fingerprinting, solver, or request handling.

## Pre-Commit Rules

**ALWAYS run lint and tests before EVERY commit. No exceptions.**

```bash
uv run ruff check wafer/ tests/
uv run pytest tests/ -x -q
```

If ruff fails, fix with `uv run ruff check --fix wafer/ tests/` and verify again.

## Testing

See `docs/site-list.md` for WAF test sites and maintenance rules.

**NEVER rapid-fire requests during development.** WAF-protected sites will block you after a few fast requests. One request at a time, 5+ seconds between requests, stop when blocked. **Exception:** intentional challenge triggering to verify solvers.

**NEVER mark a manual smoke test as passed unless the specific behavior was actually observed against the real site.** If a WAF challenge doesn't trigger, the smoke test is untestable -not passed. Local mocks don't count.

## wreq

Wraps wreq **0.12.0+** (the `Emulation` API, formerly rnet). See `docs/ref-wreq.md` for TlsOptions gotchas and HTTP/2 header duplication rules.

**When upgrading wreq**, check for new Chrome Emulation profiles (e.g. Chrome146). If found:
1. Update `DEFAULT_EMULATION` in `wafer/_base.py` to the newest Chrome profile.
2. Add the new version's real build number to `_CHROME_BUILDS` in `wafer/_fingerprint.py`. Get it from `versionhistory.googleapis.com/v1/chrome/platforms/mac/channels/stable/versions`. **Also refresh `_EDGE_BUILDS` (same file)** with the new Edge major's REAL Edge stable build (Edge ships a DISTINCT build number from Chromium - e.g. Edge147 = 147.0.3912.51 while Chromium147 = 147.0.7727.24). Source from the Microsoft Edge release notes / Update Catalog, or wire-verify the build wreq emits (`Edg/...` token + `sec-ch-ua-full-version-list` against tls.peet.ws). Without this, the "Microsoft Edge" sec-ch-ua brand silently carries Chrome's build.
3. Update `test_profiles_discovered` count and `test_newest_first` version in `tests/test_fingerprint.py`. Also update every "newest Chrome" assertion in test_fingerprint.py (sec-ch-ua `"NNN"` strings, `Emulation.ChromeNNN` references in `TestFingerprintManager` and `TestSessionFingerprint`). Keep `test_chrome_NNN` regression cases in `TestSecChUaGeneration` and any `Chrome130`/`Chrome133` fixtures unchanged.
4. **Also check the changelog for kwarg renames at the Client level or in TlsOptions/Http2Options.** wreq silently accepts unknown kwargs - typos and stale names will not error, they will silently be ignored. v0.11 renamed `verify`→`tls_verify` (and other `tls_`-prefixed Client kwargs) and replaced `TlsOptions(key_shares_limit: int)` with `TlsOptions(key_shares: Sequence[KeyShare])`. After every wreq bump, wire-verify Safari + Dart against tls.peet.ws and run the badssl/expired test for `tls_verify`.
5. After bumping, if `repr(Emulation.ChromeX)` changes shape (e.g. v0.11 changed it from `"Emulation.ChromeX"` to `"Profile.ChromeX"`), update any hardcoded `repr()` string comparisons in tests and docs.
6. **Also refresh `FIREFOX_LADDER_EMULATION` and `EDGE_LADDER_EMULATION` in `wafer/_fingerprint.py`** to the newest available Firefox/Edge `Emulation` profiles. These pin the cross-family rotation ladder (`ROTATION_LADDER`); like `DEFAULT_EMULATION` they are concrete members, not auto-discovered, so a wreq bump that adds newer Firefox/Edge profiles leaves them silently stale (the ladder keeps rotating to an old browser version) unless you bump them by hand.

## Conventions

- No `from __future__ import annotations`
- Logging via `logging.getLogger("wafer")`, never print()
- wreq's `Emulation` enum is the source of truth for browser fingerprints
- Always default to the newest Chrome `Emulation` profile available (currently Chrome147)
- Solver docs live in `docs/ref-*.md` -one per WAF type
- Mousse changes must update both `wafer/browser/mousse/README.md` and `README.md`
- **Keep `llms.txt` up to date.** It is the implementation guide for LLMs helping users write code that uses wafer (not for contributors). When adding/changing public API, session params, response fields, error types, challenge types, profiles, or browser solver features, update `llms.txt` to match. Rules for what belongs:
  - **Include:** exact types/defaults, concurrency safety, lifecycle/cleanup, error behavior (what raises what and when), how features interact (e.g. per-request headers vs embed mode), scoping (per-session, per-hostname, per-domain), gotchas that cause silent bugs (shared BrowserSolver, no close(), CWD-relative paths)
  - **Exclude:** internal implementation details (wreq HeaderMap, TlsOptions vs Emulation), contributor workflows (tests, lint, releases), file layout, dependency internals (wreq platform wheels), anything the consumer never touches

## Optional Dependencies

There are exactly two install modes: `pip install wafer-py` (core) and `pip install wafer-py[browser]` (everything). **Never create additional extras** like `[audio]`, `[vision]`, `[models]`, etc. If a dependency is needed for browser solving or advanced challenge solving (Whisper, ONNX, Pillow, OpenCV, Patchright), it goes in `[browser]`. The only question is: does it need a browser or not?

## What NOT to Build

- Proxy rotation/pooling -separate concern, just accept a proxy URL
- HTML parsing -wafer is an HTTP client, not a scraper
- CLI tool -library only, meant to be imported
- Concurrency helpers (batch/parallel requests) -callers manage their own parallelism
- Adaptive concurrency -out of scope for an HTTP client

## Releasing

Version is derived from git tags via `hatch-vcs` -never hardcode a version in `pyproject.toml`. To release: `git tag v0.X.0 && git push origin v0.X.0`. The `publish.yml` Action handles the rest.

## Commands

```bash
uv venv && uv pip install -e ".[dev]"
uv run pytest tests/ -x -q
uv run ruff check wafer/ tests/
uv run python -m wafer.browser.mousse
```
