"""Live recon + solve: drag/slider CAPTCHAs across multiple sites.

Tests the drag solver against:
1. GeeTest demo (baseline — known working)
2. bilibili.com (GeeTest v4 on login)
3. kucoin.com (GeeTest v4 on login)
4. AliExpress (Alibaba Cloud CAPTCHA 2.0 — recon only)

Usage:
    uv run python tests/live_drag_sites.py [site]

    site: geetest | bilibili | kucoin | aliexpress | all
    Default: geetest
"""

import json
import logging
import random
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

from patchright.sync_api import sync_playwright

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)-7s %(message)s",
)
log = logging.getLogger("live_drag")

EXTENSION_PATH = str(Path("wafer/browser/_extensions/screenxy").resolve())
OUT = Path("recon_output/drag_sites")
OUT.mkdir(parents=True, exist_ok=True)


def launch_browser(p):
    """Launch Chrome with screenxy extension."""
    browser = p.chromium.launch(
        channel="chrome",
        headless=False,
        args=[
            f"--disable-extensions-except={EXTENSION_PATH}",
            f"--load-extension={EXTENSION_PATH}",
        ],
    )
    page = browser.new_page(viewport={"width": 1280, "height": 800})
    return browser, page


def setup_image_intercept(page, domains):
    """Capture PNG images from specified domains."""
    captured = {"bg": None, "piece": None, "all_images": []}

    def _on_response(response):
        try:
            host = urlparse(response.url).hostname or ""
            if not any(host == d or host.endswith("." + d) for d in domains):
                return
            ct = response.headers.get("content-type", "")
            if "image/" not in ct and not any(
                response.url.endswith(ext)
                for ext in (".png", ".jpg", ".jpeg", ".webp")
            ):
                return
            body = response.body()
            if not body:
                return
            path = urlparse(response.url).path
            fname = path.split("/")[-1][:60]
            log.info(
                "[NET] image %s (%d bytes) from %s",
                fname, len(body), host,
            )
            captured["all_images"].append({
                "url": response.url,
                "size": len(body),
                "type": ct,
            })
            if "image/png" in ct or response.url.endswith(".png"):
                if len(body) > 20_000:
                    captured["bg"] = body
                    log.info("  -> classified as BG")
                else:
                    captured["piece"] = body
                    log.info("  -> classified as PIECE")
        except Exception:
            pass

    page.on("response", _on_response)
    return captured


def dump_captcha_dom(page, site_name):
    """Dump CAPTCHA-related DOM structure for analysis."""
    out_dir = OUT / site_name
    out_dir.mkdir(parents=True, exist_ok=True)

    # Check for GeeTest
    gt_info = page.evaluate("""() => {
        const r = {};
        r.hasInitGeetest4 = typeof window.initGeetest4 === 'function';
        r.hasGeetestSlider = !!document.querySelector('.geetest_slider');
        r.hasGeetestBtn = !!document.querySelector('.geetest_btn_click');
        r.hasGeetestBg = !!document.querySelector('.geetest_bg');
        r.geetestClasses = [...new Set(
            [...document.querySelectorAll('[class*="geetest"]')]
                .flatMap(e => [...e.classList]
                    .filter(c => c.startsWith('geetest_')))
        )].sort();
        // Check for Alibaba CAPTCHA
        r.hasAliyunCaptcha = typeof window.initAliyunCaptcha === 'function';
        r.hasAliyunModule = !!document.querySelector(
            '.aliyunCaptcha-module'
        );
        // Look for any captcha-related elements
        r.captchaElements = [...document.querySelectorAll(
            '[class*="captcha"],[class*="CAPTCHA"],[class*="slider"],'
            + '[class*="puzzle"],[id*="captcha"],[id*="CAPTCHA"]'
        )].map(e => ({
            tag: e.tagName,
            id: e.id,
            cls: e.className.toString().substring(0, 200),
            visible: e.offsetWidth > 0 && e.offsetHeight > 0,
        }));
        // Check iframes
        r.iframes = [...document.querySelectorAll('iframe')].map(f => ({
            src: (f.src || '').substring(0, 200),
            w: f.offsetWidth,
            h: f.offsetHeight,
        }));
        return r;
    }""")

    (out_dir / "captcha_dom.json").write_text(
        json.dumps(gt_info, indent=2)
    )
    log.info("DOM dump for %s: %s", site_name, json.dumps(gt_info, indent=2))
    return gt_info


# ── Site-specific handlers ────────────────────────────────────────────


def test_geetest_demo(page, captured):
    """GeeTest demo — known working baseline."""
    from wafer.browser._cv import find_notch
    from wafer.browser._drag import (
        _check_result,
        _extract_images_from_dom,
        _get_geometry,
        _png_width,
        _wait_for_puzzle,
    )
    from wafer.browser._solver import BrowserSolver

    solver = BrowserSolver()
    solver._ensure_recordings()

    url = "https://www.geetest.com/en/adaptive-captcha-demo"
    log.info("Navigating to %s", url)
    page.goto(url, wait_until="domcontentloaded")
    time.sleep(5)

    page.evaluate("window.scrollBy(0, 400)")
    time.sleep(1)

    # Select Slide CAPTCHA
    tab = page.locator(".tab-item.tab-item-1").first
    tab.scroll_into_view_if_needed(timeout=5000)
    tab.click(timeout=5000)
    time.sleep(2)

    # Select Bind style
    el = page.locator("text=Bind to button").first
    el.scroll_into_view_if_needed(timeout=3000)
    el.click(timeout=3000)
    time.sleep(1)

    # Reset captured images
    captured["bg"] = None
    captured["piece"] = None

    # Trigger
    btn = page.locator("text=login").first
    btn.scroll_into_view_if_needed(timeout=3000)
    btn.click(timeout=5000)

    vendor = "geetest"
    if not _wait_for_puzzle(page, vendor, 15000):
        log.error("Puzzle not visible")
        return False

    # Wait for images
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        if captured["bg"] and captured["piece"]:
            break
        time.sleep(0.2)

    bg_png = captured["bg"]
    piece_png = captured["piece"]

    if not bg_png or not piece_png:
        bg_dom, piece_dom = _extract_images_from_dom(page, vendor)
        bg_png = bg_png or bg_dom
        piece_png = piece_png or piece_dom

    if not bg_png or not piece_png:
        log.error("Could not get images")
        return False

    x_offset, confidence = find_notch(bg_png, piece_png)
    log.info("CV: x=%d conf=%.3f", x_offset, confidence)

    if confidence < 0.10:
        return False

    geom = _get_geometry(page, vendor)
    if not geom:
        return False
    handle_box, track_width, _ = geom

    handle_cx = handle_box["x"] + handle_box["width"] / 2
    handle_cy = handle_box["y"] + handle_box["height"] / 2
    handle_w = handle_box["width"]
    max_slide = track_width - handle_w

    native_bg_w = _png_width(bg_png)
    native_piece_w = _png_width(piece_png)

    if native_bg_w <= native_piece_w:
        return False

    handle_target = (
        x_offset / (native_bg_w - native_piece_w)
    ) * max_slide
    end_x = handle_cx + handle_target
    end_y = handle_cy

    viewport = page.viewport_size
    idle_x = viewport["width"] * random.uniform(0.3, 0.7)
    idle_y = viewport["height"] * random.uniform(0.3, 0.5)
    page.mouse.move(idle_x, idle_y)

    solver._replay_path(page, idle_x, idle_y, handle_cx, handle_cy)
    solver._replay_drag(page, handle_cx, handle_cy, end_x, end_y)

    for _ in range(10):
        time.sleep(0.3)
        result = _check_result(page, vendor)
        if result is True:
            log.info("SOLVED!")
            return True
        if result is False:
            log.info("Rejected")
            return False

    log.info("No clear result")
    return False


def test_bilibili(page, captured):
    """bilibili.com — GeeTest v4 on login page."""
    url = "https://passport.bilibili.com/login"
    log.info("Navigating to %s", url)

    try:
        page.goto(url, wait_until="domcontentloaded", timeout=15000)
    except Exception:
        log.warning("Navigation timeout (expected for Chinese site)")

    time.sleep(5)

    # Screenshot and DOM dump
    page.screenshot(
        path=str(OUT / "bilibili" / "login_page.png"), full_page=True
    )
    dom_info = dump_captcha_dom(page, "bilibili")

    # Check if GeeTest is present
    if dom_info.get("hasInitGeetest4"):
        log.info("GeeTest v4 detected on bilibili!")
    else:
        log.info("No GeeTest v4 found yet — may need to trigger")

    # Try clicking login button to trigger captcha
    # bilibili login form has username/password fields
    try:
        login_btn = page.locator(
            'button:has-text("Login"),'
            'button:has-text("登录"),'
            '.btn-login'
        ).first
        if login_btn.is_visible(timeout=3000):
            log.info("Found login button, clicking to trigger CAPTCHA...")
            login_btn.click(timeout=5000)
            time.sleep(3)

            # Re-check DOM
            dom_info = dump_captcha_dom(page, "bilibili_after_click")
            page.screenshot(
                path=str(OUT / "bilibili" / "after_click.png"),
                full_page=True,
            )
    except Exception as e:
        log.info("Login button interaction: %s", e)

    # Check for GeeTest widget
    try:
        page.wait_for_selector(
            ".geetest_bg,.geetest_slider,.geetest_btn_click",
            state="visible",
            timeout=5000,
        )
        log.info("GeeTest widget appeared!")
        page.screenshot(
            path=str(OUT / "bilibili" / "geetest_visible.png"),
            full_page=True,
        )
        return True
    except Exception:
        log.info("No GeeTest widget appeared within 5s")

    return False


def test_kucoin(page, captured):
    """kucoin.com — GeeTest v4 on login page."""
    url = "https://www.kucoin.com/login"
    log.info("Navigating to %s", url)

    try:
        page.goto(url, wait_until="domcontentloaded", timeout=15000)
    except Exception:
        log.warning("Navigation timeout")

    time.sleep(5)

    page.screenshot(
        path=str(OUT / "kucoin" / "login_page.png"), full_page=True
    )
    dom_info = dump_captcha_dom(page, "kucoin")

    if dom_info.get("hasInitGeetest4"):
        log.info("GeeTest v4 detected on kucoin!")

    # KuCoin is an SPA — GeeTest may load after interaction
    # Try filling a dummy email and clicking sign in
    try:
        email_input = page.locator(
            'input[type="email"],input[name="email"],'
            'input[placeholder*="Email"],input[placeholder*="email"]'
        ).first
        if email_input.is_visible(timeout=3000):
            log.info("Found email input, filling dummy data...")
            email_input.fill("test@example.com")
            time.sleep(1)

            # Try password
            pwd_input = page.locator(
                'input[type="password"]'
            ).first
            if pwd_input.is_visible(timeout=2000):
                pwd_input.fill("TestPassword123!")
                time.sleep(1)

            # Click sign in
            signin = page.locator(
                'button:has-text("Sign In"),'
                'button:has-text("Log In"),'
                'button[type="submit"]'
            ).first
            if signin.is_visible(timeout=2000):
                log.info("Clicking sign in to trigger CAPTCHA...")
                signin.click(timeout=5000)
                time.sleep(5)

                dom_info = dump_captcha_dom(page, "kucoin_after_submit")
                page.screenshot(
                    path=str(OUT / "kucoin" / "after_submit.png"),
                    full_page=True,
                )
    except Exception as e:
        log.info("KuCoin interaction: %s", e)

    # Check for GeeTest
    try:
        page.wait_for_selector(
            ".geetest_bg,.geetest_slider,.geetest_btn_click",
            state="visible",
            timeout=5000,
        )
        log.info("GeeTest widget appeared!")
        page.screenshot(
            path=str(OUT / "kucoin" / "geetest_visible.png"),
            full_page=True,
        )
        return True
    except Exception:
        log.info("No GeeTest widget appeared within 5s")

    return False


def test_aliexpress(page, captured):
    """AliExpress — Alibaba Cloud CAPTCHA 2.0 recon."""
    url = "https://login.aliexpress.com/"
    log.info("Navigating to %s", url)

    try:
        page.goto(url, wait_until="domcontentloaded", timeout=15000)
    except Exception:
        log.warning("Navigation timeout")

    time.sleep(5)

    (OUT / "aliexpress").mkdir(parents=True, exist_ok=True)
    page.screenshot(
        path=str(OUT / "aliexpress" / "login_page.png"), full_page=True
    )
    dump_captcha_dom(page, "aliexpress")

    # Check for Alibaba CAPTCHA
    ali_check = page.evaluate("""() => {
        const r = {};
        // Check for AliyunCaptcha
        r.hasInitAliyun = typeof window.initAliyunCaptcha === 'function';
        // Check for NoCaptcha (older Alibaba)
        r.hasNoCaptcha = typeof window.NoCaptcha === 'function';
        r.hasNoCaptchaInit = typeof window.ALIYUN_CAPTCHA === 'object';
        // Check for slider/puzzle elements
        r.sliderElements = [...document.querySelectorAll(
            '[class*="slider"],[class*="puzzle"],[class*="captcha"],'
            + '[class*="nc-"],[class*="nc_"],[id*="nc_"]'
        )].map(e => ({
            tag: e.tagName,
            id: e.id,
            cls: e.className.toString().substring(0, 200),
            visible: e.offsetWidth > 0 && e.offsetHeight > 0,
            rect: (() => {
                const b = e.getBoundingClientRect();
                return {x: b.x, y: b.y, w: b.width, h: b.height};
            })(),
        }));
        // Check for AliyunCaptcha SDK script
        r.scripts = [...document.querySelectorAll('script[src]')]
            .map(s => s.src)
            .filter(s => s.includes('captcha') || s.includes('alicdn')
                || s.includes('aliyun'));
        // Check iframes (Alibaba may use iframes)
        r.iframes = [...document.querySelectorAll('iframe')]
            .map(f => ({
                src: (f.src || '').substring(0, 300),
                w: f.offsetWidth,
                h: f.offsetHeight,
                visible: f.offsetWidth > 0 && f.offsetHeight > 0,
            }));
        return r;
    }""")

    (OUT / "aliexpress" / "alibaba_captcha_info.json").write_text(
        json.dumps(ali_check, indent=2)
    )
    log.info(
        "AliExpress CAPTCHA info: %s",
        json.dumps(ali_check, indent=2),
    )

    # Try to trigger the CAPTCHA by interacting with login form
    try:
        # Look for email/account input
        account_input = page.locator(
            'input[name="loginId"],input[name="email"],'
            'input[placeholder*="email"],input[placeholder*="Email"],'
            'input[placeholder*="account"],input[type="text"]'
        ).first
        if account_input.is_visible(timeout=5000):
            log.info("Found account input, filling...")
            account_input.fill("testuser@example.com")
            time.sleep(1)

            # Password
            pwd = page.locator('input[type="password"]').first
            if pwd.is_visible(timeout=2000):
                pwd.fill("TestPass123!")
                time.sleep(1)

            # Submit
            submit = page.locator(
                'button[type="submit"],'
                'button:has-text("Sign in"),'
                'button:has-text("Log in"),'
                'input[type="submit"]'
            ).first
            if submit.is_visible(timeout=2000):
                log.info("Clicking submit to trigger CAPTCHA...")
                submit.click(timeout=5000)
                time.sleep(5)

                # Re-check
                dump_captcha_dom(
                    page, "aliexpress_after_submit"
                )
                page.screenshot(
                    path=str(
                        OUT / "aliexpress" / "after_submit.png"
                    ),
                    full_page=True,
                )

                # Deeper check after submit
                ali_post = page.evaluate("""() => {
                    const r = {};
                    r.hasInitAliyun = (
                        typeof window.initAliyunCaptcha === 'function'
                    );
                    r.sliderElements = [
                        ...document.querySelectorAll(
                            '[class*="slider"],[class*="puzzle"],'
                            + '[class*="captcha"],[class*="nc-"],'
                            + '[class*="nc_"],[id*="nc_"],'
                            + '[class*="baxia"],[id*="baxia"]'
                        )
                    ].map(e => ({
                        tag: e.tagName,
                        id: e.id,
                        cls: e.className.toString().substring(0, 200),
                        visible: (
                            e.offsetWidth > 0 && e.offsetHeight > 0
                        ),
                    }));
                    r.iframes = [
                        ...document.querySelectorAll('iframe')
                    ].map(f => ({
                        src: (f.src || '').substring(0, 300),
                        w: f.offsetWidth,
                        h: f.offsetHeight,
                    }));
                    return r;
                }""")
                (OUT / "aliexpress" / "post_submit_info.json").write_text(
                    json.dumps(ali_post, indent=2)
                )
                log.info(
                    "Post-submit: %s",
                    json.dumps(ali_post, indent=2),
                )
    except Exception as e:
        log.info("AliExpress interaction: %s", e)

    return False  # recon only


SITES = {
    "geetest": {
        "handler": test_geetest_demo,
        "domains": {"static.geetest.com"},
    },
    "bilibili": {
        "handler": test_bilibili,
        "domains": {"static.geetest.com"},
    },
    "kucoin": {
        "handler": test_kucoin,
        "domains": {"static.geetest.com"},
    },
    "aliexpress": {
        "handler": test_aliexpress,
        "domains": {"img.alicdn.com", "captcha.alicdn.com", "o.alicdn.com"},
    },
}


def main():
    site = sys.argv[1] if len(sys.argv) > 1 else "geetest"
    sites_to_test = list(SITES.keys()) if site == "all" else [site]

    if not all(s in SITES for s in sites_to_test):
        print(f"Unknown site. Options: {', '.join(SITES.keys())}, all")
        sys.exit(1)

    with sync_playwright() as p:
        for site_name in sites_to_test:
            log.info("=" * 60)
            log.info("Testing: %s", site_name)
            log.info("=" * 60)

            site_conf = SITES[site_name]
            (OUT / site_name).mkdir(parents=True, exist_ok=True)

            browser, page = launch_browser(p)
            captured = setup_image_intercept(
                page, site_conf["domains"]
            )

            try:
                result = site_conf["handler"](page, captured)
                status = "PASS" if result else "RECON/FAIL"
                log.info(
                    "=== %s: %s ===", site_name.upper(), status
                )
            except Exception as e:
                log.error("Error testing %s: %s", site_name, e)
            finally:
                page.screenshot(
                    path=str(OUT / site_name / "final.png"),
                    full_page=True,
                )
                # Save captured image info
                if captured["all_images"]:
                    (OUT / site_name / "images.json").write_text(
                        json.dumps(
                            captured["all_images"], indent=2
                        )
                    )
                time.sleep(3)
                browser.close()


if __name__ == "__main__":
    main()
