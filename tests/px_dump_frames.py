"""Dump all frame content when a PX challenge appears.

Run with: uv run python tests/px_dump_frames.py [url]

Navigates to a PX-protected site, waits for #px-captcha to appear,
then dumps the HTML content of every frame + deep inspection of
#px-captcha children (computed styles, visibility, tag types, etc).
"""

import json
import logging
import os
import sys
import time

from wafer.browser._solver import BrowserSolver

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)

DUMP_DIR = os.path.join(os.path.dirname(__file__), "px_frame_dumps")

# JS to deeply inspect #px-captcha and all its children
INSPECT_JS = """() => {
    const el = document.querySelector('#px-captcha');
    if (!el) return {error: 'no #px-captcha'};

    function inspect(node, depth) {
        const result = {
            tag: node.tagName,
            id: node.id || null,
            className: node.className || null,
            depth: depth,
        };

        // Computed styles
        const cs = window.getComputedStyle(node);
        result.display = cs.display;
        result.visibility = cs.visibility;
        result.opacity = cs.opacity;
        result.position = cs.position;
        result.width = cs.width;
        result.height = cs.height;
        result.overflow = cs.overflow;

        // Bounding rect
        const rect = node.getBoundingClientRect();
        result.rect = {
            x: Math.round(rect.x),
            y: Math.round(rect.y),
            w: Math.round(rect.width),
            h: Math.round(rect.height),
        };

        // Attributes
        result.attrs = {};
        for (const attr of node.attributes || []) {
            result.attrs[attr.name] = attr.value.substring(0, 200);
        }

        // Text content (direct, not inherited)
        const directText = Array.from(node.childNodes)
            .filter(n => n.nodeType === 3)
            .map(n => n.textContent.trim())
            .filter(t => t)
            .join(' ');
        if (directText) result.directText = directText;

        // Special: canvas
        if (node.tagName === 'CANVAS') {
            result.canvasWidth = node.width;
            result.canvasHeight = node.height;
        }

        // Special: iframe
        if (node.tagName === 'IFRAME') {
            result.src = node.src || null;
            result.srcdoc = node.srcdoc ? node.srcdoc.substring(0, 500) : null;
            try {
                result.iframeContent = node.contentDocument
                    ? node.contentDocument.documentElement.outerHTML.substring(0, 2000)
                    : '(cross-origin or empty)';
            } catch(e) {
                result.iframeContent = '(cross-origin: ' + e.message + ')';
            }
        }

        // Recurse into children
        result.children = [];
        for (const child of node.children) {
            result.children.push(inspect(child, depth + 1));
        }

        return result;
    }

    return inspect(el, 0);
}"""


def main():
    url = sys.argv[1] if len(sys.argv) > 1 else "https://www.wayfair.com"

    solver = BrowserSolver(headless=False, solve_timeout=120)
    solver._ensure_browser()
    context = solver._create_context()
    page = context.new_page()

    print(f"Navigating to {url}")
    try:
        page.goto(url, wait_until="domcontentloaded", timeout=30000)
    except Exception as e:
        print(f"Navigation error (may be expected): {e}")

    # Poll for #px-captcha to appear
    print("Waiting for PX challenge (up to 30s)...")
    found = False
    for i in range(60):
        try:
            content = page.content()
            if "px-captcha" in content:
                print(f"PX challenge detected after {i * 0.5:.1f}s")
                found = True
                break
        except Exception:
            pass
        time.sleep(0.5)

    if not found:
        print("No PX challenge detected. Dumping page anyway.")

    # Wait for captcha to fully render
    print("Waiting 15s for captcha to fully render...")
    for i in range(30):
        time.sleep(0.5)
        n = len(page.frames)
        if i % 6 == 0:
            print(f"  {i * 0.5:.0f}s: {n} frames")

    os.makedirs(DUMP_DIR, exist_ok=True)
    site = url.split("//")[-1].split("/")[0].replace("www.", "")
    ts = time.strftime("%H%M%S")

    # --- Deep inspect #px-captcha ---
    print("\n=== #px-captcha deep inspection ===")
    try:
        tree = page.evaluate(INSPECT_JS)
        fname = f"{site}_{ts}_px-captcha-tree.json"
        fpath = os.path.join(DUMP_DIR, fname)
        with open(fpath, "w") as f:
            json.dump(tree, f, indent=2)
        print(f"Saved: {fname}")

        # Print the tree
        def print_node(node, indent=0):
            prefix = "  " * indent
            tag = node.get("tag", "?")
            rect = node.get("rect", {})
            disp = node.get("display", "?")
            vis = node.get("visibility", "?")
            opa = node.get("opacity", "?")
            dims = f"{rect.get('w', '?')}x{rect.get('h', '?')}"
            pos = f"({rect.get('x', '?')},{rect.get('y', '?')})"

            line = (
                f"{prefix}<{tag}> "
                f"display={disp} vis={vis} opacity={opa} "
                f"size={dims} pos={pos}"
            )
            if node.get("id"):
                line += f" id={node['id']}"
            if node.get("className"):
                cn = node["className"]
                if isinstance(cn, str):
                    line += f" class={cn[:60]}"
            if node.get("directText"):
                line += f" text={node['directText']!r:.60}"
            if tag == "CANVAS":
                line += (
                    f" canvas={node.get('canvasWidth')}x"
                    f"{node.get('canvasHeight')}"
                )
            if tag == "IFRAME":
                line += f" src={node.get('src', '?')!r:.80}"
                if node.get("iframeContent"):
                    line += f"\n{prefix}  iframe_content="
                    line += node["iframeContent"][:200].replace(
                        "\n", " "
                    )
            print(line)

            for child in node.get("children", []):
                print_node(child, indent + 1)

        print_node(tree)
    except Exception as e:
        print(f"Deep inspect failed: {e}")

    # --- Dump all frames ---
    print(f"\n=== Dumping {len(page.frames)} frames ===")
    for i, frame in enumerate(page.frames):
        frame_url = frame.url[:100] if frame.url else "(no url)"
        print(f"\nFrame {i}: {frame_url}")
        print(f"  Name: {frame.name!r}")

        try:
            content = frame.content()
            fname = f"{site}_{ts}_frame{i}.html"
            fpath = os.path.join(DUMP_DIR, fname)
            with open(fpath, "w") as f:
                f.write(content)
            print(f"  Saved: {fname} ({len(content)} bytes)")

            # Search for interesting text
            try:
                body_text = frame.locator("body").text_content(
                    timeout=1000
                )
                if body_text:
                    lower = body_text.lower()
                    for keyword in [
                        "press", "hold", "captcha",
                        "human", "verify",
                    ]:
                        if keyword in lower:
                            idx = lower.index(keyword)
                            start = max(0, idx - 20)
                            end = min(len(body_text), idx + 40)
                            snippet = body_text[start:end]
                            print(
                                f"  Text '{keyword}': "
                                f"...{snippet!r}..."
                            )
            except Exception:
                pass

        except Exception as e:
            print(f"  Error reading frame: {e}")

    # --- Screenshot ---
    try:
        fname = f"{site}_{ts}_screenshot.png"
        fpath = os.path.join(DUMP_DIR, fname)
        page.screenshot(path=fpath)
        print(f"\nScreenshot: {fname}")
    except Exception as e:
        print(f"\nScreenshot failed: {e}")

    # --- px-captcha outerHTML ---
    try:
        el = page.locator("#px-captcha")
        if el.count() > 0:
            outer = el.evaluate("el => el.outerHTML")
            fname = f"{site}_{ts}_px-captcha.html"
            fpath = os.path.join(DUMP_DIR, fname)
            with open(fpath, "w") as f:
                f.write(outer)
            print(
                f"Saved #px-captcha outerHTML: {fname} "
                f"({len(outer)} bytes)"
            )
    except Exception as e:
        print(f"Could not dump #px-captcha: {e}")

    print("\nKeeping browser open for 30s to inspect manually...")
    for i in range(30):
        time.sleep(1)

    context.close()
    solver.close()
    print(f"\nDumps saved to {DUMP_DIR}/")


if __name__ == "__main__":
    main()
