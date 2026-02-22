# Wafer

Anti-detection HTTP client for Python. Wraps rnet with opinionated defaults for TLS fingerprinting, challenge detection/solving, cookie caching, retry, and rate limiting.

## References

- `README.md` — full API documentation, architecture, usage examples
- `docs/site-list.md` — WAF benchmark targets organized by tier and vendor
- `docs/perimeterx.md` — PerimeterX press-and-hold solver (architecture, bugs, live results)
- `docs/kasada.md` — Kasada solver (CT/CD, open ST validation gap)
- `docs/baxia.md` — Baxia/AliExpress slider solver (stealth, behavioral signals, TMD flow)
- `docs/geetest.md` — GeeTest v4 slide CAPTCHA solver (CV, demo interaction, widget structure)
- `wafer/browser/mousse/README.md` — mouse movement recorder tool docs

## Site List Maintenance

**Keep `site-list.md` continuously up to date.** WAF challenges are intermittent — a site that passes today may challenge tomorrow. Update the list whenever:

- A site escalates to a browser challenge or interactive CAPTCHA during testing
- A previously-passing site starts returning 403s or challenge pages
- A new WAF vendor, challenge type, or unique behavior is encountered
- A site's tier changes (e.g., was Tier 2 TLS-only, now requires browser solve)
- Live testing produces new status data (pass/fail/browser-solve)

When updating, change the **Status** column and add a date + note. Don't assume a site's current behavior is permanent.

## Debugging Rules

**NEVER blame external services** (Cloudflare, Akamai, rnet, etc.) for issues. The problem is in THIS codebase. Investigate our code first, add logging, find the real cause.

**NEVER dismiss issues as "pre-existing" or "known".** Every issue is an issue. If something fails during testing, investigate the root cause and fix it.

## Pre-Commit Rules

**ALWAYS run lint and tests before EVERY commit. No exceptions.**

```bash
uv run ruff check wafer/ tests/
uv run pytest tests/ -x -q
```

If ruff fails, fix with `uv run ruff check --fix wafer/ tests/` and verify again.

## Testing

### WAF Test Sites

See `site-list.md` for URLs per WAF type. Use these for manual integration testing.

### Live Testing Rules

**NEVER rapid-fire requests during development.** WAF-protected sites will block you after a few fast requests.

- One request at a time. Verify the response before the next.
- Wait 5+ seconds between requests to the same domain.
- When blocked, stop. Don't retry. Fix the code, try again after 10+ minutes.
- Save responses to files during development. Test parsing against saved files.

**Exception: intentional challenge triggering.** When the goal is to trigger a WAF challenge (e.g., verifying a solver works), rapid requests are expected and necessary — some challenges only appear after repeated hits. In this case, ignore the spacing rules above. Still stop once blocked/challenged and verify the solver behavior before continuing.

### Smoke Test Honesty

**NEVER mark a manual smoke test as passed unless the specific behavior was actually observed against the real site.** If a WAF challenge doesn't trigger (e.g. because our fingerprint is too good), the smoke test is NOT passed — it's untestable. Mark it as unchecked with a note explaining why. Local HTTP server tests and mocks do NOT count as passing a manual smoke test. An E2E test against localhost verifies the code path works, but it does not verify the solver works against the real WAF.

### Writing Tests

- Unit tests: mock responses for challenge detectors, retry logic, cookie cache, rate limiter.
- Recorded fixtures: response headers + truncated body (no copyrighted JS from WAF vendors).
- Integration tests: manual, against real WAF test sites. Not in CI.
- **Assert behavior, not existence.** No `assert result is not None`.
- **Include negative cases.** Test that non-challenge 403s aren't misclassified.

## rnet

Wraps rnet **3.0.0rc21+** (the `Emulation` API). NOT the stable 2.x series (which uses the old `Impersonate` API). See `BUILD.md` "rnet API Reference" section for detailed gotchas and usage patterns.

### Critical: HTTP/2 Header Duplication

**NEVER send the same header at both client level AND per-request level.** rnet creates duplicate entries in HTTP/2 HEADERS frames, which strict WAFs (Cloudflare, DataDome) detect as non-browser behavior → instant 403.

The `_build_headers()` method returns a **delta** — only headers that are NEW or DIFFERENT from client-level. Static headers (Accept, sec-ch-ua, etc.) are set ONCE at client construction. Per-request only adds dynamic headers (Referer, embed headers, user overrides).

Also: **never send Host per-request** — rnet auto-sets it from the URL. Sending it per-request duplicates the `:authority` pseudo-header.

## Conventions

- Python package manager: `uv` (never pip)
- All Python runs via `uv run`
- No `from __future__ import annotations`
- Logging via `logging.getLogger("wafer")`, never print()
- rnet's `Emulation` enum is the source of truth for browser fingerprints
- Always default to the newest Chrome `Emulation` profile available (currently Chrome145)

## Documentation Pattern

**`docs/` is for long-term solver reference docs** — one per solver/WAF type. Each doc covers: status, architecture, key decisions, vendor behavior, detection signals, and test infrastructure. Keep them well-organized and essential — no task checklists, no recon procedures, no completed TODO items. Delete one-off recon scripts and task plans when done; preserve the knowledge in the solver doc.

Current solver docs: `perimeterx.md`, `kasada.md`, `baxia.md`, `geetest.md`. Add new ones as solvers are built.

## Mousse (Mouse Recorder)

Changes to mousse must update both `wafer/browser/mousse/README.md` and the "Mouse Recorder" section in `README.md`. Recording formats and targets are also referenced in `perimeterx.md` and `baxia.md` — keep consistent.

### Browse Replay in Solvers

All browser solver wait loops must use `_replay_browse_chunk()` instead of bare `time.sleep()`. This replays recorded mouse movement and scrolling during idle waits, preventing WAF VMs from detecting zero-activity bot signals. Pattern:

1. `state = solver._start_browse(page, x, y)` at solver start
2. `solver._replay_browse_chunk(page, state, N)` replacing each `time.sleep(N)`

Falls back to `time.sleep` transparently when no browse recordings are loaded.

## What NOT to Build

- Proxy rotation/pooling — separate concern, just accept a proxy URL
- HTML parsing — wafer is an HTTP client, not a scraper
- CLI tool — library only, meant to be imported
- Concurrency helpers (batch/parallel requests) — callers manage their own parallelism
- Adaptive concurrency — out of scope for an HTTP client

## Web Fetching

**For general research/browsing**: Use fetchaller MCP tools (`mcp__fetchaller__*`) instead of WebFetch/WebSearch. No domain restrictions, bypasses bot protection.

**For testing wafer functionality**: ALWAYS use wafer itself (`uv run python -c "import wafer; ..."` or test scripts). Never use fetchaller to test links, WAF challenges, solver behavior, or anything wafer is supposed to handle — that defeats the purpose.

## Releasing

Version is derived from git tags via `hatch-vcs` — never hardcode a version in `pyproject.toml`. To release:

```bash
git tag v0.2.0
git push origin v0.2.0
```

The `publish.yml` GitHub Action builds, tests, and publishes to PyPI automatically via trusted publishing (no API tokens).

## Commands

```bash
uv venv && uv pip install -e ".[dev]"
uv run pytest tests/ -x -q
uv run ruff check wafer/ tests/
uv run python -m wafer.browser.mousse
```
