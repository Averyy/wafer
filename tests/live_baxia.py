"""Live test: Baxia NoCaptcha with webdriver patch.

Injects stealth script directly into HTML responses via
page.route() to ensure it runs before any page scripts.

Usage:
    uv run python tests/live_baxia.py
"""

import logging
import time
from pathlib import Path

import rnet
from patchright.sync_api import sync_playwright

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)-8s %(levelname)-7s %(message)s",
)
log = logging.getLogger("live_baxia")

OUT = Path("recon_output/baxia")
OUT.mkdir(parents=True, exist_ok=True)

KEYWORDS = [
    "phone-case", "laptop-stand", "earbuds", "keyboard",
    "headphones", "mouse-pad", "usb-cable", "power-bank",
    "screen-protector", "tablet-case", "webcam", "monitor-stand",
    "hdmi-cable", "wireless-charger", "bluetooth-speaker",
    "led-strip", "desk-lamp", "phone-holder", "car-charger",
    "smart-watch", "fitness-tracker", "air-purifier", "humidifier",
    "drone", "projector", "ring-light", "microphone", "router",
    "ssd-drive", "ram-stick", "graphics-card", "cpu-cooler",
]

STEALTH_SCRIPT = b"""<script>
Object.defineProperty(Navigator.prototype, 'webdriver', {
    get: () => false,
    configurable: true,
});
if (window.chrome && !window.chrome.runtime) {
    window.chrome.runtime = {
        connect: function() {},
        sendMessage: function() {},
    };
}
</script>"""


def trigger_tmd() -> str | None:
    """Rapid-fire AliExpress search until TMD triggers."""
    client = rnet.blocking.Client(emulation=rnet.Emulation.Chrome145)
    for i, kw in enumerate(KEYWORDS):
        url = f"https://www.aliexpress.com/w/wholesale-{kw}.html"
        log.info("[%d/%d] GET %s", i + 1, len(KEYWORDS), url)
        try:
            resp = client.get(url)
        except Exception as e:
            log.warning("Error: %s", e)
            time.sleep(0.3)
            continue
        body = resp.text()
        if "/_____tmd_____/punish" in body:
            log.info("TMD triggered after %d requests!", i + 1)
            return url
        log.info("  -> %d (%d bytes)", resp.status.as_int(), len(body))
    return None


def main():
    tmd_url = trigger_tmd()
    if not tmd_url:
        log.error("TMD not triggered")
        return

    from wafer.browser._drag import solve_baxia
    from wafer.browser._solver import BrowserSolver

    solver = BrowserSolver()
    solver._ensure_recordings()

    with sync_playwright() as p:
        browser = p.chromium.launch(channel="chrome", headless=False)
        page = browser.new_page(viewport={"width": 1280, "height": 720})

        # Intercept navigation requests and inject stealth script
        def stealth_route(route):
            # Only intercept document navigations, not sub-resources
            if route.request.resource_type != "document":
                route.continue_()
                return
            try:
                resp = route.fetch()
            except Exception:
                route.continue_()
                return
            body = resp.body()
            # Inject stealth at the start
            if b"<head>" in body:
                body = body.replace(
                    b"<head>", b"<head>" + STEALTH_SCRIPT
                )
            elif b"<script>" in body:
                # TMD page is just a <script> tag, no HTML structure
                body = STEALTH_SCRIPT + body
            route.fulfill(
                status=resp.status,
                headers=resp.headers,
                body=body,
            )

        page.route("**/*", stealth_route)

        # Navigate
        log.info("Navigating to %s", tmd_url)
        try:
            page.goto(tmd_url, wait_until="domcontentloaded", timeout=15000)
        except Exception as e:
            log.warning("Navigation: %s", e)

        time.sleep(5)
        log.info("URL: %s", page.url[:200])

        # Verify
        wd = page.evaluate("() => navigator.webdriver")
        log.info("navigator.webdriver = %s", wd)

        page.screenshot(path=str(OUT / "01_punish.png"))

        # Wait for slider
        for _ in range(20):
            has = page.evaluate("() => !!document.querySelector('#nc_1_n1z')")
            if has:
                break
            time.sleep(0.5)
        else:
            log.error("Slider not found!")
            page.screenshot(path=str(OUT / "no_slider.png"))
            browser.close()
            return

        log.info("Slider found!")

        # Solve
        log.info("Calling solve_baxia()...")
        solved = solve_baxia(solver, page, timeout_ms=30000)

        if solved:
            log.info("=== BAXIA SOLVE SUCCESS ===")
            time.sleep(3)
            page.screenshot(path=str(OUT / "03_solved.png"))
            log.info("Final URL: %s", page.url[:200])
            cookies = page.context.cookies()
            log.info("Cookies (%d):", len(cookies))
            for c in cookies:
                log.info(
                    "  %s=%s... (domain=%s)",
                    c["name"],
                    str(c.get("value", ""))[:30],
                    c.get("domain", "?"),
                )
        else:
            log.error("=== BAXIA SOLVE FAILED ===")
            page.screenshot(path=str(OUT / "03_failed.png"))

        time.sleep(2)
        browser.close()


if __name__ == "__main__":
    main()
