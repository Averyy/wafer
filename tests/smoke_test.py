#!/usr/bin/env python3
"""Multi-site smoke test for wafer.

Tests all sites from site-list.md using wafer's SyncSession to verify:
1. TLS fingerprinting works against real WAFs
2. Challenge detection correctly identifies WAF types
3. Site list statuses are accurate and up to date

Usage:
    # TLS-only (default) — tests fingerprinting + challenge detection
    uv run python tests/smoke_test.py

    # With browser solver
    uv run python tests/smoke_test.py --browser

    # Filter by tier, WAF, or single URL
    uv run python tests/smoke_test.py --tier 2
    uv run python tests/smoke_test.py --waf cloudflare
    uv run python tests/smoke_test.py --url vinted.com

    # Save results to JSON
    uv run python tests/smoke_test.py --json tests/smoke_results.json
"""

import argparse
import datetime
import json
import logging
import sys
import time

from wafer import SyncSession
from wafer._challenge import ChallengeType, detect_challenge
from wafer._errors import (
    ChallengeDetected,
    ConnectionFailed,
    RateLimited,
    WaferError,
)

# ── Site list ──────────────────────────────────────────────────────────
# (tier, waf, url) — hardcoded from site-list.md to avoid fragile
# markdown parsing. Keep in sync manually.

SITES: list[tuple[int, str, str]] = [
    # Tier 0: No Protection
    (0, "none", "https://httpbin.org/get"),
    (0, "none", "https://httpbin.org/headers"),
    (0, "none", "https://httpbin.org/anything"),
    (0, "none", "https://example.com"),
    # Tier 1: UA Check Only
    (1, "akamai", "https://ticketmaster.com"),
    (1, "minimal", "https://nytimes.com"),
    # Tier 2: TLS Fingerprint Required
    (2, "cloudflare", "https://vinted.com"),
    (2, "akamai", "https://aircanada.com"),
    (2, "akamai", "https://crateandbarrel.com"),
    (2, "akamai", "https://nike.com"),
    (2, "akamai", "https://ebay.com"),
    (2, "perimeterx", "https://stockx.com"),
    (2, "perimeterx", "https://digikey.com"),
    (2, "awswaf", "https://traveloka.com"),
    (2, "awswaf", "https://similarweb.com"),
    # Tier 3: Browser Challenge
    (3, "cloudflare", "https://scrapingcourse.com/cloudflare-challenge"),
    (3, "cloudflare", "https://scrapingcourse.com/antibot-challenge"),
    (3, "cloudflare", "https://nowsecure.nl"),
    (3, "cloudflare", "https://hltv.org"),
    (3, "cloudflare", "https://crunchbase.com"),
    (3, "cloudflare", "https://capterra.com/categories"),
    (3, "cloudflare", "https://fiverr.com"),
    (3, "cloudflare", "https://miata.net"),
    (3, "cloudflare", "https://glassdoor.com"),
    (3, "turnstile", "https://scrapingcourse.com/login/cf-turnstile"),
    (3, "turnstile", "https://2captcha.com/demo/cloudflare-turnstile"),
    (3, "datadome", "https://g2.com"),
    (3, "datadome", "https://airbnb.com"),
    (3, "datadome", "https://neimanmarcus.com"),
    (3, "datadome", "https://idealista.com"),
    (3, "datadome", "https://ra.co"),
    (3, "datadome", "https://klwines.com"),
    (3, "datadome", "https://leboncoin.fr"),
    (3, "datadome", "https://allegro.pl"),
    (3, "datadome", "https://deezer.com"),
    (3, "akamai", "https://lowes.com"),
    (3, "akamai", "https://expedia.com"),
    (3, "akamai", "https://marriott.com"),
    (3, "akamai", "https://southwest.com"),
    (3, "akamai", "https://united.com"),
    (3, "akamai", "https://adidas.com"),
    (3, "datadome", "https://mouser.com"),
    (3, "akamai", "https://bestbuy.com"),
    (3, "akamai", "https://hyatt.com"),
    (3, "akamai", "https://starbucks.com"),
    (3, "imperva", "https://amadeus.com"),
    (3, "imperva", "https://anz.com.au"),
    (3, "imperva", "https://www.hkbea.com/html/en/index.html"),
    (3, "imperva", "https://appdev.pwc.com"),
    (3, "awswaf", "https://amazon.com"),
    (3, "awswaf", "https://booking.com"),
    (3, "datadome", "https://shutterstock.com"),
    (3, "awswaf", "https://stubhub.com"),
    (3, "kasada", "https://realestate.com.au"),
    (3, "kasada", "https://hyatt.com"),
    (3, "kasada", "https://scheels.com"),
    (3, "kasada", "https://vividseats.com"),
    (3, "kasada", "https://footlocker.co.uk"),
    (3, "kasada", "https://wizzair.com"),
    # New sites (2026-02-21) — verified via TLS + browser-solve testing
    # Tier 2: TLS pass
    (2, "kasada", "https://www.godaddy.com"),
    (2, "kasada", "https://www.arcteryx.com"),
    (2, "datadome", "https://www.marketwatch.com"),
    (2, "akamai", "https://www.delta.com"),
    (2, "akamai", "https://www.costco.com"),
    (2, "akamai", "https://www.kroger.com"),
    (2, "akamai", "https://www.samsclub.com"),
    (2, "cloudflare", "https://www.car.gr"),
    (2, "cloudflare", "https://www.draftkings.com"),
    (2, "cloudflare", "https://www.nbcsports.com"),
    (2, "imperva", "https://www.whoscored.com"),
    (2, "imperva", "https://www.psacard.com"),
    (2, "perimeterx", "https://www.weedmaps.com"),
    (2, "perimeterx", "https://www.citygear.com"),
    (2, "perimeterx", "https://www.asda.com"),
    (2, "shape", "https://www.chase.com"),
    (2, "unknown", "https://www.footdistrict.com"),
    # Tier 3: Browser challenge (solve verified)
    (3, "cloudflare", "https://kick.com"),
    (3, "cloudflare", "https://fbref.com"),
    (3, "datadome", "https://www.tripadvisor.com"),
    (5, "cloudflare", "https://www.manta.com"),  # CF passes browser, no cf_clearance
    # Tier 4: Interactive CAPTCHA
    (4, "perimeterx", "https://wayfair.com/v/account/authentication/login"),
    (4, "perimeterx", "https://zillow.com"),
    (4, "perimeterx", "https://walmart.com/blocked"),
    (4, "perimeterx", "https://fanduel.com"),
    (4, "perimeterx", "https://goodrx.com"),
    (4, "perimeterx", "https://bhphotovideo.com"),
    (4, "perimeterx", "https://academy.com"),
    (4, "perimeterx", "https://belk.com"),
    (4, "kasada", "https://realtor.com"),
    (4, "akamai", "https://homedepot.com"),
    (4, "perimeterx", "https://indeed.com"),
    (4, "perimeterx", "https://priceline.com"),
    (4, "perimeterx", "https://lanebryant.com"),
    (4, "perimeterx", "https://thenorthface.com"),
    (4, "perimeterx", "https://carters.com"),
    (4, "perimeterx", "https://ralphlauren.com.au"),
    (4, "perimeterx", "https://bkstr.com"),
    (4, "datadome", "https://pokemoncenter.com"),
    (4, "datadome", "https://etsy.com"),
    (4, "datadome", "https://soundcloud.com"),
    (4, "datadome", "https://seatgeek.com"),
    (4, "perimeterx", "https://www.hibbett.com"),
    # Tier 5: Behavioral / In-House
    (5, "in-house", "https://www.tiktok.com"),
    (5, "in-house", "https://www.temu.com"),
    (5, "datadome", "https://www.reddit.com"),
    (5, "in-house", "https://www.facebook.com/marketplace/"),
    (5, "in-house", "https://artists.spotify.com"),
    (5, "in-house", "https://google.com/search?q=test"),
    (5, "in-house", "https://bing.com/search?q=test"),
    (5, "in-house", "https://shein.com"),
    (5, "in-house", "https://linkedin.com"),
    (5, "in-house", "https://instagram.com"),
    (5, "in-house", "https://bet365.com"),
    (5, "riskified", "https://ssense.com"),
    (5, "kasada", "https://canadagoose.com"),
    (5, "cloudfront", "https://farfetch.com"),
    (5, "none", "https://skyscanner.com"),
]


def classify_result(
    status: int, size: int, challenge: ChallengeType | None, error: str | None
) -> str:
    """Classify a smoke test result."""
    if error:
        return "error"
    if challenge:
        return "challenge"
    if status in (403, 429) and not challenge:
        return "blocked"
    if 200 <= status < 400:
        return "pass"
    return "blocked"


def run_one(
    session: SyncSession, url: str, timeout_s: float = 15.0
) -> dict:
    """Test a single URL. Returns a result dict."""
    result = {
        "url": url,
        "status": None,
        "size": 0,
        "challenge": None,
        "was_retried": False,
        "elapsed": 0.0,
        "error": None,
        "classification": None,
        "final_url": None,
    }

    t0 = time.monotonic()
    try:
        resp = session.get(
            url,
            timeout=datetime.timedelta(seconds=timeout_s),
        )
        result["status"] = resp.status_code
        result["size"] = len(resp.content)
        result["challenge"] = resp.challenge_type
        result["was_retried"] = resp.was_retried
        result["elapsed"] = round(resp.elapsed, 2)
        result["final_url"] = resp.url

        # Also run detect_challenge on the raw response for extra info
        if resp.text:
            detected = detect_challenge(
                resp.status_code, resp.headers, resp.text
            )
            if detected:
                result["challenge"] = detected.value

    except ChallengeDetected as e:
        result["status"] = e.status_code
        result["challenge"] = e.challenge_type
        result["error"] = f"ChallengeDetected: {e.challenge_type}"
        result["elapsed"] = round(time.monotonic() - t0, 2)
    except RateLimited:
        result["status"] = 429
        result["error"] = "RateLimited"
        result["elapsed"] = round(time.monotonic() - t0, 2)
    except ConnectionFailed as e:
        result["error"] = f"ConnectionFailed: {e.reason[:80]}"
        result["elapsed"] = round(time.monotonic() - t0, 2)
    except WaferError as e:
        result["error"] = f"{type(e).__name__}: {str(e)[:80]}"
        result["elapsed"] = round(time.monotonic() - t0, 2)
    except Exception as e:
        result["error"] = f"{type(e).__name__}: {str(e)[:80]}"
        result["elapsed"] = round(time.monotonic() - t0, 2)

    result["classification"] = classify_result(
        result["status"] or 0,
        result["size"],
        ChallengeType(result["challenge"]) if result["challenge"] else None,
        result["error"],
    )
    return result


def format_size(n: int) -> str:
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f}MB"
    if n >= 1_000:
        return f"{n / 1_000:.0f}KB"
    return f"{n}B"


def print_header():
    print(
        f"{'Tier':<5} {'WAF (expected)':<14} {'URL':<45} "
        f"{'Status':<7} {'Size':<8} {'Challenge':<14} "
        f"{'Result':<10} {'Time':<6} {'Notes'}"
    )
    print("-" * 160)


def print_row(tier: int, waf: str, r: dict):
    # Shorten URL for display
    url = r["url"].replace("https://", "").replace("http://", "")
    if len(url) > 43:
        url = url[:40] + "..."

    status_str = str(r["status"] or "---")
    size_str = format_size(r["size"]) if r["size"] else "---"
    challenge_str = r["challenge"] or "---"
    time_str = f"{r['elapsed']:.1f}s"

    notes = ""
    if r["error"]:
        notes = r["error"][:50]
    elif r["final_url"] and r["final_url"] != r["url"]:
        final_short = r["final_url"].replace("https://", "").replace("http://", "")
        if len(final_short) > 40:
            final_short = final_short[:37] + "..."
        notes = f"-> {final_short}"

    # Color classification
    cls = r["classification"]
    if cls == "pass":
        cls_str = "PASS"
    elif cls == "challenge":
        cls_str = "CHALLENGE"
    elif cls == "blocked":
        cls_str = "BLOCKED"
    else:
        cls_str = "ERROR"

    print(
        f"{tier:<5} {waf:<14} {url:<45} "
        f"{status_str:<7} {size_str:<8} {challenge_str:<14} "
        f"{cls_str:<10} {time_str:<6} {notes}"
    )


def main():
    parser = argparse.ArgumentParser(description="Wafer multi-site smoke test")
    parser.add_argument(
        "--browser", action="store_true", help="Enable browser solver"
    )
    parser.add_argument(
        "--tier", type=int, help="Only test sites at this tier"
    )
    parser.add_argument(
        "--waf", type=str, help="Only test sites with this WAF type"
    )
    parser.add_argument(
        "--url", type=str, help="Only test sites matching this URL substring"
    )
    parser.add_argument(
        "--json", type=str, metavar="PATH",
        help="Save results to JSON file",
    )
    parser.add_argument(
        "--timeout", type=float, default=15.0,
        help="Per-request timeout in seconds (default: 15)",
    )
    parser.add_argument(
        "--delay", type=float, default=2.0,
        help="Delay between requests in seconds (default: 2)",
    )
    args = parser.parse_args()

    # Filter sites
    sites = SITES
    if args.tier is not None:
        sites = [(t, w, u) for t, w, u in sites if t == args.tier]
    if args.waf:
        waf_lower = args.waf.lower()
        sites = [(t, w, u) for t, w, u in sites if waf_lower in w.lower()]
    if args.url:
        url_lower = args.url.lower()
        sites = [
            (t, w, u) for t, w, u in sites if url_lower in u.lower()
        ]

    if not sites:
        print("No sites match the given filters.")
        sys.exit(1)

    print(f"Testing {len(sites)} sites (TLS-only, no browser solver)")
    if args.browser:
        print("  Browser solver: ENABLED")
    print()

    # Configure logging: wafer at WARNING to suppress retry spam
    logging.basicConfig(
        format="%(levelname)s %(name)s: %(message)s", level=logging.WARNING
    )
    # But show challenge detections
    logging.getLogger("wafer").setLevel(logging.WARNING)

    # Build session
    session_kwargs = {
        "max_retries": 1,
        "max_rotations": 1,
        "timeout": datetime.timedelta(seconds=args.timeout),
        "connect_timeout": datetime.timedelta(seconds=args.timeout),
        "cache_dir": None,  # No cookie persistence for smoke test
    }

    if args.browser:
        from wafer.browser import BrowserSolver
        session_kwargs["browser_solver"] = BrowserSolver()

    session = SyncSession(**session_kwargs)

    print_header()

    results = []
    counts = {"pass": 0, "challenge": 0, "blocked": 0, "error": 0}

    for i, (tier, waf, url) in enumerate(sites):
        r = run_one(session, url, timeout_s=args.timeout)
        r["tier"] = tier
        r["waf_expected"] = waf
        results.append(r)
        counts[r["classification"]] += 1
        print_row(tier, waf, r)

        # Delay between different domains (not after last)
        if i < len(sites) - 1:
            time.sleep(args.delay)

    # Summary
    print()
    print("=" * 60)
    print(f"  Total: {len(results)}")
    print(f"  Pass:      {counts['pass']}")
    print(f"  Challenge: {counts['challenge']}")
    print(f"  Blocked:   {counts['blocked']}")
    print(f"  Error:     {counts['error']}")
    print("=" * 60)

    # Save JSON if requested
    json_path = args.json
    if json_path:
        output = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "total": len(results),
            "counts": counts,
            "results": results,
        }
        with open(json_path, "w") as f:
            json.dump(output, f, indent=2, default=str)
        print(f"\nResults saved to {json_path}")


if __name__ == "__main__":
    main()
