"""Headless Chrome must be indistinguishable from headed Chrome, everywhere.

Launches the installed Chrome against a local server (no network traffic) and
compares every surface a site can read, in every context a page can open, with
real headed Chrome on the same machine:

- ``navigator.userAgent``, ``userAgentData`` brands and high-entropy hints, and
  ``navigator.languages``, in the top document, a cross-site iframe, an iframe
  nested back on the top site (A->B->A), a worker inside the iframe, and a
  dedicated, a shared and a service worker;
- the ``User-Agent`` and ``sec-ch-ua*`` headers of every request, including the
  opt-in high-entropy ones;
- devicePixelRatio, screen, colorDepth and outer size in every frame;
- ``navigator.userActivation.hasBeenActive`` on a page nobody touched;
- a shared worker created again after its page closed, which must still run.

Each of these leaked before this suite existed: service and shared workers
said ``HeadlessChrome``, iframes reported ``architecture: x86`` and
``platformVersion: 10.15.7``, iframes reported their own screen and a
devicePixelRatio of 1, and the init-script fallback marked every page as
user-activated.

macOS only: the window patch and the forced device scale factor are macOS
facts. Run with ``WAFER_LIVE=1``; it opens a headed Chrome window.
"""

import asyncio
import json
import os
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        os.environ.get("WAFER_LIVE") != "1",
        reason="launches system Chrome; set WAFER_LIVE=1 to run",
    ),
    pytest.mark.skipif(sys.platform != "darwin", reason="macOS window facts"),
]

_PROBE = r"""
async function __probe(extra) {
  const n = navigator, d = n.userAgentData;
  let he = {};
  try {
    he = await d.getHighEntropyValues(
      ['architecture', 'bitness', 'platformVersion', 'fullVersionList']);
  } catch (e) {}
  return Object.assign({
    ua: n.userAgent,
    brands: d.brands.map(b => b.brand + '/' + b.version).join(', '),
    full: (he.fullVersionList || []).map(b => b.brand + '/' + b.version).join(', '),
    arch: he.architecture, bitness: he.bitness, pv: he.platformVersion,
    langs: n.languages.join(','),
  }, extra || {});
}
// Every trusted input event this frame receives, so an activation can be
// traced to what caused it.
var __inputs = [];
['keydown', 'mousedown', 'pointerdown', 'touchend', 'click'].forEach(function (t) {
  addEventListener(t, function (e) {
    if (e.isTrusted) __inputs.push(t + (e.key ? ':' + e.key : ''));
  }, true);
});
function __frame() {
  return {dpr: devicePixelRatio, screen: screen.width + 'x' + screen.height,
          colorDepth: screen.colorDepth, outer: outerWidth + 'x' + outerHeight,
          avail: screen.availWidth + 'x' + screen.availHeight + '@' +
                 screen.availLeft + ',' + screen.availTop,
          delta: (outerWidth - innerWidth) + 'x' + (outerHeight - innerHeight),
          active: navigator.userActivation.hasBeenActive,
          inputs: __inputs.slice(0, 10)};
}
function __report(src, r) {
  return fetch('/report?src=' + src + '&d=' + encodeURIComponent(JSON.stringify(r)));
}
"""

_CONTEXTS = {
    "top",
    "iframe",
    "aba",
    "iframe-worker",
    "worker",
    "shared",
    "blob-shared",
    "sw",
    "iframe-sw",
}
_FRAMES = ("top", "iframe", "aba")
# A shared worker started from a blob: URL, as Kasada's are. Its script is
# loaded with no request, so only the driver preload (hardened_driver_env)
# holds it: without it, 15-17 of 100 read empty high-entropy hints.
_BLOB_SHARED = (
    "new SharedWorker(URL.createObjectURL(new Blob([%s + \"__probe().then(r => "
    "fetch('\" + location.origin + \"/report?src=blob-shared&d=' + "
    "encodeURIComponent(JSON.stringify(r))))\"], {type: 'text/javascript'})))"
    ".port.start();" % json.dumps(_PROBE)
)
_HEADERS = (
    "user-agent",
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
    "sec-ch-ua-arch",
    "sec-ch-ua-bitness",
    "sec-ch-ua-platform-version",
    "sec-ch-ua-full-version-list",
)
_ACCEPT_CH = (
    "Sec-CH-UA-Arch, Sec-CH-UA-Bitness, Sec-CH-UA-Full-Version-List, "
    "Sec-CH-UA-Platform-Version"
)


class _Recorder:
    def __init__(self):
        self.requests = []
        self.reports = {}

    def clear(self):
        self.requests.clear()
        self.reports.clear()


def _server():
    record = _Recorder()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            url = urlparse(self.path)
            port = self.server.server_address[1]
            record.requests.append(
                {"path": url.path, **{h: self.headers.get(h) for h in _HEADERS}}
            )
            ctype, extra = "text/html", {}
            frame = (
                "setTimeout(() => __probe(__frame())"
                ".then(r => __report('{0}', r)), 1500)"
            )
            if url.path == "/report":
                q = parse_qs(url.query)
                record.reports[q["src"][0]] = json.loads(q["d"][0])
                body = "ok"
            elif url.path == "/top":
                extra["Accept-CH"] = _ACCEPT_CH
                body = (
                    f'<iframe src="http://localhost:{port}/iframe"></iframe>'
                    f"<script>{_PROBE} new Worker('/worker.js');"
                    "new SharedWorker('/shared.js').port.start();"
                    f"{_BLOB_SHARED}"
                    "navigator.serviceWorker.register('/sw.js');"
                    f"fetch('/xhr'); {frame.format('top')}</script>"
                )
            elif url.path == "/iframe":
                body = (
                    f'<iframe src="http://127.0.0.1:{port}/aba"></iframe>'
                    f"<script>{_PROBE} new Worker('/iframe-worker.js');"
                    # Registered by the cross-site iframe: no main-script
                    # throttle, so only the script-fetch hold keeps it.
                    "navigator.serviceWorker.register('/iframe-sw.js');"
                    f"{frame.format('iframe')}</script>"
                )
            elif url.path == "/late":
                # An iframe created after load, while the solver thread sleeps.
                body = (
                    "<script>setTimeout(() => { const f = document.createElement"
                    f"('iframe'); f.src = 'http://localhost:{port}/late-child?c=' "
                    "+ Date.now(); document.body.appendChild(f); }, 300)</script>"
                )
            elif url.path == "/late-child":
                body = (
                    "<script>const c = +new URLSearchParams(location.search)"
                    ".get('c'); __r = Date.now() - c; fetch('/report?src=late&d='"
                    " + encodeURIComponent(JSON.stringify(__r)))</script>"
                )
            elif url.path == "/opener":
                body = (
                    '<button id="open" onclick="window.open(\'/popup\')">'
                    "open</button>"
                )
            elif url.path == "/popup":
                # Read the moment the popup's first document runs (the driver
                # preload gives it wafer's override before Playwright resumes
                # it), again later, and on its next page.
                body = (
                    f"<script>{_PROBE} __probe(__frame())"
                    ".then(r => __report('popup-first', r));"
                    " setTimeout(() => __probe(__frame())"
                    ".then(r => __report('popup-later', r))"
                    ".then(() => { location.href = '/popup2'; }), 800)</script>"
                )
            elif url.path == "/popup2":
                body = (
                    f"<script>{_PROBE} __probe(__frame())"
                    ".then(r => __report('popup-next', r))</script>"
                )
            elif url.path == "/restart":
                body = "<script>new SharedWorker('/shared.js').port.start()</script>"
            elif url.path == "/aba":
                body = f"<script>{_PROBE} {frame.format('aba')}</script>"
            elif url.path in ("/worker.js", "/shared.js", "/iframe-worker.js"):
                ctype = "application/javascript"
                name = url.path[1:-3]
                body = (
                    f"{_PROBE} fetch('/from-{name}');"
                    f" __probe().then(r => __report('{name}', r));"
                )
            elif url.path == "/iframe-sw.js":
                ctype = "application/javascript"
                # Reads the moment its script runs, the strictest case.
                body = _PROBE + " __probe().then(r => __report('iframe-sw', r));"
            elif url.path == "/sw.js":
                ctype = "application/javascript"
                body = _PROBE + (
                    " self.addEventListener('install', e => { self.skipWaiting();"
                    " e.waitUntil(fetch('/from-sw').then(() => __probe())"
                    ".then(r => __report('sw', r))); });"
                )
            else:
                body = "ok"
            data = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            for key, value in extra.items():
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, record, f"http://127.0.0.1:{server.server_address[1]}/top"


@pytest.fixture(scope="module")
def site():
    pytest.importorskip("patchright")
    server, record, url = _server()
    yield record, url
    server.shutdown()


def _collect(page, record, url, after_goto=None):
    record.clear()
    page.goto(url)
    if after_goto is not None:
        after_goto(page)
    for _ in range(40):
        page.wait_for_timeout(250)
        if _CONTEXTS <= set(record.reports):
            break
    return {"reports": dict(record.reports), "requests": list(record.requests)}


async def _collect_async(page, record, url):
    record.clear()
    await page.goto(url)
    for _ in range(40):
        await page.wait_for_timeout(250)
        if _CONTEXTS <= set(record.reports):
            break
    return {"reports": dict(record.reports), "requests": list(record.requests)}


# The documented UA probe launch gets no network (see README).
_PROBE_ARGS = ["--proxy-server=http://127.0.0.1:9", "--disable-background-networking"]


def _launch_kwargs(headless, user_agent=None, probe=False):
    from wafer.browser import hardened_launch_config

    kwargs = {"user_agent": user_agent} if user_agent else {}
    config = hardened_launch_config(headless=headless, **kwargs)
    return {
        "headless": headless,
        "channel": "chrome",
        "args": list(config.args) + (_PROBE_ARGS if probe else []),
        "ignore_default_args": list(config.ignore_default_args),
    }


@pytest.fixture(scope="module")
def truth(site):
    """Real headed Chrome, with no wafer hardening at all."""
    from patchright.sync_api import sync_playwright

    record, url = site
    with sync_playwright() as p:
        browser = p.chromium.launch(**_launch_kwargs(False))
        try:
            page = browser.new_context(no_viewport=True).new_page()
            observed = _collect(page, record, url)
        finally:
            browser.close()
    assert _CONTEXTS <= set(observed["reports"]), "headed Chrome did not report"
    return observed


def _assert_indistinguishable(observed, truth, *, native=True):
    """*native*: the page runs on the launch's real display (no_viewport), so
    its geometry must equal headed Chrome's outright, not only agree across
    frames. Viewport emulation gets the window script's geometry instead."""
    reports, requests = observed["reports"], observed["requests"]
    assert _CONTEXTS <= set(reports), f"missing contexts: {_CONTEXTS - set(reports)}"
    blob = json.dumps(observed)
    assert "HeadlessChrome" not in blob

    for field in ("ua", "brands", "full", "arch", "bitness", "pv", "langs"):
        expected = truth["reports"]["top"][field]
        wrong = {
            name: reports[name].get(field)
            for name in sorted(_CONTEXTS)
            if reports[name].get(field) != expected
        }
        assert not wrong, (
            f"{field} differs from headed Chrome ({expected!r}) in {wrong}"
        )

    for field in ("dpr", "screen", "colorDepth", "outer", "avail"):
        values = {name: reports[name][field] for name in _FRAMES}
        assert len(set(values.values())) == 1, (field, values)
    assert reports["top"]["dpr"] == truth["reports"]["top"]["dpr"]
    if native:
        # The window size is the browser's own; the rest is the display's.
        for field in ("screen", "colorDepth", "avail", "delta"):
            assert reports["top"][field] == truth["reports"]["top"][field], (
                field,
                reports["top"][field],
                truth["reports"]["top"][field],
            )
    active = [name for name in _FRAMES if reports[name]["active"]]
    inputs = {name: reports[name].get("inputs") for name in _FRAMES}
    assert not active, (
        f"userActivation.hasBeenActive with no input in {active}; "
        f"trusted input events seen: {inputs}"
    )

    expected = {r["path"]: r for r in truth["requests"] if r["path"] != "/report"}
    for request in requests:
        if request["path"] in expected:
            for header in _HEADERS:
                assert request[header] == expected[request["path"]][header], (
                    request["path"],
                    header,
                )


def _harden_headless(record, url, *, emulate=False):
    from patchright.sync_api import sync_playwright

    from wafer.browser import harden_page, hardened_driver_env, scrub_headless_ua

    with hardened_driver_env(), sync_playwright() as p:
        first = p.chromium.launch(**_launch_kwargs(True, probe=True))
        ua = scrub_headless_ua(first.new_page().evaluate("navigator.userAgent"))
        first.close()
        browser = p.chromium.launch(**_launch_kwargs(True, user_agent=ua))
        try:
            if emulate:
                context = browser.new_context(
                    viewport={"width": 1440, "height": 900}, device_scale_factor=2
                )
            else:
                context = browser.new_context(no_viewport=True)
            page = context.new_page()
            harden_page(page, headless=True)
            return _collect(page, record, url)
        finally:
            browser.close()


def test_harden_page_headless(site, truth):
    _assert_indistinguishable(_harden_headless(*site), truth)


def test_harden_page_with_viewport_emulation(site, truth):
    # A caller who emulates a viewport gets the window script's geometry:
    # consistent across frames, but its own screen rather than the display's.
    observed = _harden_headless(*site, emulate=True)
    _assert_indistinguishable(observed, truth, native=False)


def test_restarted_shared_worker_runs(site, truth):
    """A shared worker created again after its page closed must run, held.

    Chrome keeps its target while wafer's session is attached and starts it
    paused for that session, announcing no attach; until wafer resumed it on
    Inspector.targetReloadedAfterCrash, the second one never ran.
    """
    from patchright.sync_api import sync_playwright

    from wafer.browser import harden_page, hardened_driver_env, scrub_headless_ua

    record, url = site
    restart = url.rsplit("/", 1)[0] + "/restart"
    top = truth["reports"]["top"]
    with hardened_driver_env(), sync_playwright() as p:
        first = p.chromium.launch(**_launch_kwargs(True, probe=True))
        ua = scrub_headless_ua(first.new_page().evaluate("navigator.userAgent"))
        first.close()
        browser = p.chromium.launch(**_launch_kwargs(True, user_agent=ua))
        try:
            context = browser.new_context(no_viewport=True)
            for round_ in range(3):
                page = context.new_page()
                harden_page(page, headless=True)
                record.clear()
                page.goto(restart)
                for _ in range(20):
                    page.wait_for_timeout(250)
                    if "shared" in record.reports:
                        break
                report = record.reports.get("shared")
                assert report is not None, f"round {round_}: shared worker never ran"
                for field in ("ua", "full", "arch", "pv"):
                    assert report[field] == top[field], (round_, field, report[field])
                page.close()
                # The worker terminates once its last page is gone.
                other = context.new_page()
                other.wait_for_timeout(1500)
                other.close()
        finally:
            browser.close()


def test_harden_page_async_persistent_headless(site, truth):
    from patchright.async_api import async_playwright

    from wafer.browser import (
        harden_page_async,
        hardened_driver_env,
        scrub_headless_ua,
    )

    record, url = site

    async def run():
        with hardened_driver_env():
            manager = async_playwright()
            p = await manager.__aenter__()
        try:
            first = await p.chromium.launch(**_launch_kwargs(True, probe=True))
            page = await first.new_page()
            ua = scrub_headless_ua(await page.evaluate("navigator.userAgent"))
            await first.close()
            with tempfile.TemporaryDirectory() as profile:
                context = await p.chromium.launch_persistent_context(
                    profile,
                    no_viewport=True,
                    **_launch_kwargs(True, user_agent=ua),
                )
                try:
                    page = await context.new_page()
                    await harden_page_async(page, headless=True)
                    return await _collect_async(page, record, url)
                finally:
                    await context.close()
        finally:
            await manager.__aexit__(None, None, None)

    _assert_indistinguishable(asyncio.run(run()), truth)


@pytest.mark.parametrize("headless", [True, False])
def test_browser_solver(site, truth, headless):
    from wafer.browser import BrowserSolver

    record, url = site
    solver = BrowserSolver(headless=headless)
    try:

        def run():
            solver._ensure_browser()
            # A headed solver sets its UA once identity is captured; every
            # later context used to carry it, and Playwright's metadata with it.
            solver._capture_preflight_identity()
            context = solver._create_context()
            try:
                page = context.new_page()
                solver._setup_headless_patches(page)

                def solver_reads(page):
                    # What a solve does right after navigation; none of it
                    # may mark the page user-activated before it reports.
                    from wafer.browser._solver import _DOCUMENT_LENGTH, _quiet_read

                    solver._verify_headless_patches(page)
                    _quiet_read(page, _DOCUMENT_LENGTH)

                return _collect(page, record, url, after_goto=solver_reads)
            finally:
                context.close()

        observed = solver._run_on_worker(run)
    finally:
        solver.close()
    _assert_indistinguishable(observed, truth)


def test_solver_sleeps_release_late_iframes(site):
    """A new iframe is attached paused until this thread releases it.

    Sync Playwright delivers the event that does so only inside a Playwright
    call, so a plain time.sleep in a solver loop held an iframe created
    mid-sleep for the rest of it: its first script ran 1730ms after creation
    under a 2s sleep, against 18ms unhardened. Solver sleeps go through
    wafer.browser._pump.idle, which keeps events flowing.
    """
    from wafer.browser import BrowserSolver
    from wafer.browser._pump import idle

    record, url = site
    late_url = url.rsplit("/", 1)[0] + "/late"
    solver = BrowserSolver(headless=True)
    try:

        def run():
            solver._ensure_browser()
            context = solver._create_context()
            try:
                page = context.new_page()
                solver._setup_headless_patches(page)
                record.clear()
                page.goto(late_url)
                idle(2.0)
                return record.reports.get("late")
            finally:
                context.close()

        delay_ms = solver._run_on_worker(run)
    finally:
        solver.close()
    assert delay_ms is not None, "the late iframe never ran"
    assert delay_ms < 300, f"late iframe's first script ran {delay_ms}ms after creation"


def test_popups_are_hardened(site, truth):
    from patchright.sync_api import sync_playwright

    from wafer.browser import harden_page, hardened_driver_env, scrub_headless_ua

    record, url = site
    opener = url.rsplit("/", 1)[0] + "/opener"
    with hardened_driver_env(), sync_playwright() as p:
        first = p.chromium.launch(**_launch_kwargs(True, probe=True))
        ua = scrub_headless_ua(first.new_page().evaluate("navigator.userAgent"))
        first.close()
        browser = p.chromium.launch(**_launch_kwargs(True, user_agent=ua))
        try:
            context = browser.new_context(no_viewport=True)
            page = context.new_page()
            harden_page(page, headless=True)
            record.clear()
            page.goto(opener)
            page.click("#open")
            for _ in range(40):
                page.wait_for_timeout(250)
                if {"popup-first", "popup-later", "popup-next"} <= set(record.reports):
                    break
            reports = dict(record.reports)
            requests = list(record.requests)
        finally:
            browser.close()
    top = truth["reports"]["top"]
    for name in ("popup-first", "popup-later", "popup-next"):
        assert name in reports, f"{name} never reported"
        for field in (
            "ua", "brands", "full", "arch", "pv", "colorDepth", "dpr", "screen", "avail"
        ):
            got = reports[name][field]
            assert got == top[field], (name, field, got)
    # The popup's own document request carries the same client hints.
    expected = next(r for r in truth["requests"] if r["path"] == "/top")
    popup_request = next(r for r in requests if r["path"] == "/popup")
    for header in ("user-agent", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform"):
        assert popup_request[header] == expected[header], header
