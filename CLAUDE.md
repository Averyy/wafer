# Wafer

Anti-detection HTTP client for Python. Wraps rnet with opinionated defaults for TLS fingerprinting, challenge detection/solving, cookie caching, retry, and rate limiting.

## Debugging Rules

**NEVER blame external services** (Cloudflare, Akamai, rnet, etc.) for issues. The problem is in THIS codebase. Investigate our code first, add logging, find the real cause.

**NEVER dismiss issues as "pre-existing" or "known".** Every issue is an issue. If something fails during testing, investigate the root cause and fix it.

**NEVER assume a dependency can't do something without reading its source.** When something "doesn't work" in rnet, Patchright, Playwright, or any other dependency, the most likely cause is wrong usage -not a missing feature. Read the actual source code to find correct APIs, field names, and calling conventions before concluding something is impossible.

## Web Fetching

**For general research/browsing**: Use fetchaller MCP tools (`mcp__fetchaller__*`) instead of WebFetch/WebSearch. No domain restrictions, bypasses bot protection.

**For testing wafer functionality**: ALWAYS use wafer itself (`uv run python -c "import wafer; ..."` or test scripts). Never use fetchaller to test links, WAF challenges, solver behavior, or anything wafer is supposed to handle -that defeats the purpose.

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

## rnet

Wraps rnet **3.0.0rc21+** (the `Emulation` API). NOT the stable 2.x series. See `docs/ref-rnet.md` for TlsOptions gotchas and HTTP/2 header duplication rules.

**When upgrading rnet**, check for new Chrome Emulation profiles (e.g. Chrome146). If found:
1. Update `DEFAULT_EMULATION` in `wafer/_base.py` to the newest Chrome profile.
2. Add the new version's real build number to `_CHROME_BUILDS` in `wafer/_fingerprint.py`. Get it from `versionhistory.googleapis.com/v1/chrome/platforms/mac/channels/stable/versions`.
3. Update `test_profiles_discovered` count and `test_newest_first` version in `tests/test_fingerprint.py`.

## Conventions

- Python package manager: `uv` (never pip)
- All Python runs via `uv run`
- No `from __future__ import annotations`
- Logging via `logging.getLogger("wafer")`, never print()
- rnet's `Emulation` enum is the source of truth for browser fingerprints
- Always default to the newest Chrome `Emulation` profile available (currently Chrome145)
- Solver docs live in `docs/ref-*.md` -one per WAF type
- Mousse changes must update both `wafer/browser/mousse/README.md` and `README.md`
- **Keep `llms.txt` up to date.** It is the implementation guide for LLMs helping users write code that uses wafer (not for contributors). When adding/changing public API, session params, response fields, error types, challenge types, profiles, or browser solver features, update `llms.txt` to match. Rules for what belongs:
  - **Include:** exact types/defaults, concurrency safety, lifecycle/cleanup, error behavior (what raises what and when), how features interact (e.g. per-request headers vs embed mode), scoping (per-session, per-hostname, per-domain), gotchas that cause silent bugs (shared BrowserSolver, no close(), CWD-relative paths)
  - **Exclude:** internal implementation details (rnet HeaderMap, TlsOptions vs Emulation), contributor workflows (tests, lint, releases), file layout, dependency internals (rnet platform wheels), anything the consumer never touches

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
