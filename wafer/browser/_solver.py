"""Patchright-based browser challenge solving.

This module contains the core ``BrowserSolver`` class: browser
lifecycle, extension management, recording loading, mouse replay
methods, and the ``solve()`` / ``intercept_iframe()`` dispatch.

WAF-specific logic lives in dedicated modules:

- ``_cloudflare`` — Cloudflare Turnstile
- ``_akamai`` — Akamai _abck
- ``_datadome`` — DataDome
- ``_awswaf`` — AWS WAF JS challenge
- ``_perimeterx`` — PerimeterX press-and-hold
- ``_shape`` — F5 Shape interstitial
- ``_imperva`` — Imperva / Incapsula reese84
- ``_drag`` — GeeTest / Alibaba drag/slider puzzle
- ``_hcaptcha`` — hCaptcha checkbox
- ``_recaptcha`` — reCAPTCHA v2 checkbox
- ``_recaptcha_grid`` — reCAPTCHA v2 image grid (EfficientNet + D-FINE)
"""

import asyncio
import atexit
import contextlib
import csv
import importlib.resources
import io
import ipaddress
import itertools
import json
import logging
import math
import os
import queue
import random
import re
import subprocess
import sys
import tempfile
import threading
import time
import weakref
from concurrent.futures import (
    Future,
)
from concurrent.futures import (
    TimeoutError as FutureTimeoutError,
)
from dataclasses import dataclass, field
from urllib.parse import parse_qs, unquote, urlparse

from wafer._cookies import browser_cookie_matches_host, registrable_domain
from wafer._errors import ResponseTooLarge
from wafer._fingerprint import chrome_full_version
from wafer._solvers import (
    is_cookie_gate,
    is_reddit_captcha_gate,
    is_reddit_verification,
)
from wafer.browser._pump import bind_page, idle, unbind_page

logger = logging.getLogger("wafer")


class _DaemonSerialExecutor:
    """One cancellable-at-process-exit worker without executor atexit joins.

    Patchright objects are thread-affine, so BrowserSolver needs a stable
    single worker. ``ThreadPoolExecutor`` registers every non-daemon worker
    with CPython's private interpreter-exit join registry; after a bounded
    ``close(timeout=...)`` that registry can still hold a process hostage.
    This deliberately tiny serial executor owns a daemon worker instead.
    Normal close joins it; a timed-out close abandons only process-local
    browser work and cannot prevent a container/interpreter from exiting.
    """

    def __init__(self, thread_name_prefix: str) -> None:
        self._queue: queue.SimpleQueue = queue.SimpleQueue()
        self._closed = False
        self._lock = threading.Lock()
        self._thread = threading.Thread(
            target=self._run,
            name=thread_name_prefix,
            daemon=True,
        )
        self._thread.start()

    def submit(self, callback, /, *args, **kwargs) -> Future:
        with self._lock:
            if self._closed:
                raise RuntimeError("BrowserSolver is closed")
            future = Future()
            self._queue.put((future, callback, args, kwargs))
            return future

    def _run(self) -> None:
        while True:
            item = self._queue.get()
            if item is None:
                return
            future, callback, args, kwargs = item
            if not future.set_running_or_notify_cancel():
                continue
            try:
                future.set_result(callback(*args, **kwargs))
            except BaseException as exc:
                future.set_exception(exc)

    def shutdown(self, wait: bool = True) -> None:
        with self._lock:
            if not self._closed:
                self._closed = True
                self._queue.put(None)
        if wait:
            self._thread.join()


def _system_chrome_executable() -> str | None:
    """Return a usable branded Chrome binary for Patchright's chrome channel."""

    if sys.platform == "darwin":
        candidates = [
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        ]
    elif sys.platform == "win32":
        program_files = os.environ.get("PROGRAMFILES", r"C:\Program Files")
        program_files_x86 = os.environ.get(
            "PROGRAMFILES(X86)", r"C:\Program Files (x86)"
        )
        local_app_data = os.environ.get("LOCALAPPDATA", "")
        candidates = [
            os.path.join(
                program_files, "Google", "Chrome", "Application", "chrome.exe"
            ),
            os.path.join(
                program_files_x86,
                "Google",
                "Chrome",
                "Application",
                "chrome.exe",
            ),
        ]
        if local_app_data:
            candidates.append(
                os.path.join(
                    local_app_data,
                    "Google",
                    "Chrome",
                    "Application",
                    "chrome.exe",
                )
            )
    else:
        candidates = [
            "/opt/google/chrome/chrome",
            "/usr/bin/google-chrome",
            "/usr/bin/google-chrome-stable",
        ]
    for candidate in candidates:
        if os.access(candidate, os.R_OK | os.X_OK):
            return candidate
    return None


_CHROME_VERSION_RE = re.compile(
    r"(?:Google Chrome(?: for Testing)?|Chromium|Chrome)\s+"
    r"(\d+\.\d+\.\d+\.\d+)(?:\s|$)"
)


def _browser_executable_version(path: str, timeout: float | None = None) -> str:
    """Return Chrome's exact version, rejecting unusable binaries."""

    if not os.access(path, os.R_OK | os.X_OK):
        raise RuntimeError("Browser executable is not a readable, executable file")
    try:
        result = subprocess.run(
            [path, "--version"],
            capture_output=True,
            check=False,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("Could not determine browser executable version") from exc
    output = f"{result.stdout}\n{result.stderr}"
    match = _CHROME_VERSION_RE.search(output)
    if result.returncode != 0 or match is None:
        raise RuntimeError("Browser executable did not report a Chrome version")
    return match.group(1)


# Hard ceiling on a single top-level navigation inside a solve. A page that
# has not reached domcontentloaded by then is stalled, and the solver needs the
# rest of the budget far more than the navigation does.
_MAX_NAVIGATION_MS = 60_000


def _navigation_budget_ms(deadline: float) -> int:
    """Bound one navigation so it cannot consume the whole solve deadline."""

    remaining_ms = max(0.0, deadline - time.monotonic()) * 1000
    return max(1, int(min(remaining_ms * 0.5, _MAX_NAVIGATION_MS)))


def _valid_browser_url(value: str) -> bool:
    """Whether a value is structurally safe for a browser navigation."""

    if (
        not isinstance(value, str)
        or not value
        or len(value) > 8192
        or any(ord(char) <= 0x20 or ord(char) == 0x7F for char in value)
    ):
        return False
    try:
        parsed = urlparse(value)
        port = parsed.port
    except (TypeError, ValueError):
        return False
    return (
        parsed.scheme in {"http", "https"}
        and bool(parsed.hostname)
        and parsed.username is None
        and parsed.password is None
        and port != 0
    )


def _cookie_structure(cookies: list[dict]) -> list[dict[str, object]]:
    """Return a bounded, value-free cookie diagnostic summary."""

    return [
        {
            "name": str(cookie.get("name", "")),
            "domain": str(cookie.get("domain", "")),
            "path": str(cookie.get("path", "/")),
            "secure": bool(cookie.get("secure", False)),
            "same_site": str(cookie.get("sameSite", "")),
        }
        for cookie in cookies[:16]
    ]


def _sleep_before_deadline(deadline: float, maximum: float) -> bool:
    """Sleep for a positive bounded interval without crossing a deadline."""

    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return False
    idle(min(maximum, remaining))
    return True


_REDDIT_BROWSER_CHALLENGE_RE = re.compile(
    r"blocked by network security|reddit\s*-\s*please wait for verification",
    re.IGNORECASE,
)


def _is_reddit_solve_page(url: str) -> bool:
    """Whether the browser is on Reddit's fixed anonymous solve page."""

    try:
        parsed = urlparse(url)
        port = parsed.port
    except (TypeError, ValueError):
        return False
    return (
        parsed.scheme == "https"
        and (parsed.hostname or "").rstrip(".").lower() == "www.reddit.com"
        and port in (None, 443)
        and parsed.path in ("", "/")
    )


def _reddit_browser_cookie_evidence(page) -> bool:
    """Check only cookies applicable to the fixed Reddit solve origin."""

    from wafer._solvers import (
        REDDIT_SOLVE_ORIGIN,
        reddit_has_cookie_evidence,
    )

    try:
        cookies = page.context.cookies(REDDIT_SOLVE_ORIGIN)
    except Exception:
        return False
    names = {
        str(cookie.get("name", ""))
        for cookie in cookies
        if isinstance(cookie, dict)
    }
    return reddit_has_cookie_evidence(names)


def _wait_for_reddit(page, timeout_ms: int) -> bool:
    """Establish Reddit cookies on the fixed HTML origin, with one reload."""

    if not _is_reddit_solve_page(page.url):
        try:
            parsed = urlparse(page.url)
            observed_host = (parsed.hostname or "").rstrip(".").lower()
            observed_path = parsed.path or "/"
        except (TypeError, ValueError):
            observed_host = "invalid"
            observed_path = "invalid"
        # Do not log the query or fragment: either may contain opaque values.
        logger.warning(
            "Reddit browser solve refused a non-root navigation "
            "(host=%s path=%s)",
            observed_host,
            observed_path,
        )
        return False

    deadline = time.monotonic() + max(0, timeout_ms) / 1000
    if _reddit_browser_cookie_evidence(page):
        return True

    # Give the verification document a short chance to run before refreshing.
    # A refresh of this HTML origin is the observed recovery path; refreshing
    # the blocked JSON URL cannot execute Reddit's verification JavaScript.
    remaining_ms = max(0, int((deadline - time.monotonic()) * 1000))
    if remaining_ms <= 0:
        return False
    try:
        page.wait_for_timeout(min(1000, max(1, remaining_ms // 4)))
    except Exception:
        pass
    if _reddit_browser_cookie_evidence(page):
        return True

    remaining_ms = max(0, int((deadline - time.monotonic()) * 1000))
    if remaining_ms <= 0:
        return False
    try:
        page.reload(
            wait_until="domcontentloaded",
            timeout=max(1, min(remaining_ms, _MAX_NAVIGATION_MS)),
        )
    except Exception as exc:
        logger.debug("Reddit browser reload failed (%s)", type(exc).__name__)

    remaining_ms = max(0, int((deadline - time.monotonic()) * 1000))
    if remaining_ms > 0:
        try:
            page.wait_for_timeout(min(2000, remaining_ms))
        except Exception:
            pass
    return _reddit_browser_cookie_evidence(page)


def _is_passthrough_challenge_html(html: str) -> bool:
    """Reject structurally identifiable WAF bodies in shared passthroughs."""

    head = html[:10000].lower()
    return (
        "kpsdk" in head
        or "captcha-delivery" in head
        or ("akamai" in head and "_abck" in head)
        or "perimeterx" in head
        or "px-captcha" in head
        or "reese84" in head
        or "just a moment" in head
        or "cf_chl" in head
        or "challenge-platform" in head
        or "chl_page" in head
        # Reddit's network-security copy can occur near the end of a ~190 KiB
        # Shreddit response, so it must not be limited to the generic 10 KiB
        # marker prefix.
        or _REDDIT_BROWSER_CHALLENGE_RE.search(html) is not None
        # Structural, so a Reddit wording change cannot leak the page.
        or is_reddit_verification(html)
        or is_reddit_captcha_gate(html)
        # A site's own "Continue" gate behind the WAF (fccid.io): the session
        # solves it inline on the replay, so it is never content.
        or is_cookie_gate(html)
    )


_CLOUDFLARE_ABSENT_BLOCK_MARKERS = (
    "checking your browser",
    "attention required",
    "enable javascript and cookies",
    "unusual traffic",
    "request blocked",
    "access denied",
)


def _is_cloudflare_absent_challenge_html(html: str) -> bool:
    """Reject challenge/block copy only on the Cloudflare-absent path.

    The prose markers are intentionally not part of the shared post-solve
    validator: legitimate application pages and inline translation bundles
    commonly contain phrases such as "access denied".
    """

    head = html[:10000].lower()
    return _is_passthrough_challenge_html(html) or any(
        marker in head for marker in _CLOUDFLARE_ABSENT_BLOCK_MARKERS
    )


def _origin_path_identity(parsed) -> tuple[str, str, int | None, str]:
    """Return a URL identity stable across query/fragment history rewrites."""

    port = parsed.port
    if port is None:
        if parsed.scheme == "https":
            port = 443
        elif parsed.scheme == "http":
            port = 80
    return (
        parsed.scheme,
        (parsed.hostname or "").rstrip(".").lower(),
        port,
        parsed.path or "/",
    )


def _network_url_identity(parsed) -> tuple[str, str, int | None, str, str]:
    """Return the request/response URL identity, excluding only fragments."""

    return (*_origin_path_identity(parsed), parsed.query)


def _main_document_status(records: list[tuple], landed) -> int | None:
    """Status of the latest main-frame document served for ``landed``.

    ``records`` holds ``(url, status, response)`` for every main-frame
    document response in order. Query and fragment are ignored, as a
    challenge's own reload often adds and then strips a token query. None
    when the page never had a document response of its own (a client-side
    route change).
    """
    target = _origin_path_identity(landed)
    for record_url, status, *_ in reversed(records):
        try:
            if _origin_path_identity(urlparse(record_url)) == target:
                return status
        except ValueError:
            continue
    return None


def _main_document_response(records: list[tuple], landed):
    """The Playwright response for the latest main-frame document at ``landed``.

    Returns None when no matching document was recorded.
    """
    target = _origin_path_identity(landed)
    for record_url, _status, response in reversed(records):
        try:
            if _origin_path_identity(urlparse(record_url)) == target:
                return response
        except ValueError:
            continue
    return None


# Each response's header read, failed or not, so it happens once.
_HEADER_READS: "weakref.WeakKeyDictionary" = weakref.WeakKeyDictionary()


def _response_headers(response) -> tuple[dict[str, str], list[str]]:
    """Read a Playwright response's headers without collapsing Set-Cookie.

    Read once per response and remembered, a failed read included. Patchright
    caches a pending future before asking the driver for raw headers, and a
    failed request (the browser closed under a timed-out render) leaves it
    unresolved forever, so any later read on that response never returns.
    render() reads its final response twice, for the content type and for
    the returned headers, and that second read wedged the worker, and the
    close() behind it, after a reCAPTCHA solve timed out (2026-10-06).
    """
    try:
        read = _HEADER_READS.get(response)
    except TypeError:  # not weakly referenceable (a test double)
        return _read_response_headers(response)
    if read is None:
        read = _read_response_headers(response)
        _HEADER_READS[response] = read
    headers, set_cookie = read
    return dict(headers), list(set_cookie)


def _read_response_headers(response) -> tuple[dict[str, str], list[str]]:
    headers: dict[str, str] = {}
    raw_headers_read = False
    try:
        all_headers = response.all_headers()
        raw_headers_read = True
        if isinstance(all_headers, dict):
            headers = {
                str(name).lower(): str(value)
                for name, value in all_headers.items()
            }
    except Exception:
        try:
            headers = {
                str(name).lower(): str(value)
                for name, value in response.headers.items()
            }
        except Exception:
            pass

    # Patchright/Chrome exposes the decoded response body via response.body().
    # Wire framing and compression headers would describe different bytes.
    for name in ("content-encoding", "content-length", "transfer-encoding"):
        headers.pop(name, None)

    set_cookie: list[str] = []
    # Never retry the raw headers after a failed read. Patchright caches a
    # pending future before asking the driver, and a failed request (the
    # browser closed under a timed-out render) leaves it unresolved forever,
    # so a second call on this response never returns. That wedged the
    # worker, and an unbounded close() behind it, after every render that
    # timed out on a challenge (2026-10-05).
    if not raw_headers_read:
        logger.debug(
            "Raw response headers unavailable; Set-Cookie not captured for %s",
            getattr(response, "url", "?"),
        )
        return headers, set_cookie
    try:
        for entry in response.headers_array():
            if (
                isinstance(entry, dict)
                and str(entry.get("name", "")).lower() == "set-cookie"
            ):
                set_cookie.append(str(entry.get("value", "")))
    except Exception:
        pass
    return headers, set_cookie


# Rendered-fetch settle tuning. The DOM-stability poll runs after the
# network has gone quiet, so a short interval and a handful of samples are
# enough to tell "hydration finished" from "still writing nodes"; the cap
# keeps a permanently animating page from eating the caller's whole budget.
_RENDER_POLL_INTERVAL = 0.25
_RENDER_STABLE_POLLS = 3
_RENDER_SETTLE_CAP = 10.0
# Post-solve phase bound: how long the capture may spend re-navigating
# and settling after a challenge clears, clamped to the caller deadline.
_RENDER_POST_SOLVE_SECONDS = 30.0
# The challenges whose in-place solve can outrun an ordinary render budget:
# a reCAPTCHA that escalates to image grids took 61.6s over two rounds on
# Google's /sorry/ page and up to 112s over three (2026-10-06), against the
# session's 30s default. A render that lands on one may run to the caller's
# challenge_budget instead (session.render() passes it only when the caller
# gave no timeout of its own).
_SLOW_INPLACE_CHALLENGES = frozenset({"recaptcha"})

# The only content types whose serialized DOM is the resource. Everything else
# Chrome shows inside a generated viewer document.
_RENDERABLE_CONTENT_TYPES = frozenset({"text/html", "application/xhtml+xml"})


def _rendered_headers(response) -> tuple[dict[str, str], list[str]]:
    """Headers for a serialized DOM, not for the bytes the server sent.

    The document is re-serialized from the live DOM and encoded as UTF-8, so
    the original content-type charset no longer describes it. ``_response_headers``
    already drops the framing/compression headers.
    """

    headers: dict[str, str] = {}
    set_cookie: list[str] = []
    if response is not None:
        try:
            headers, set_cookie = _response_headers(response)
        except Exception:
            headers, set_cookie = {}, []
    headers["content-type"] = "text/html; charset=utf-8"
    return headers, set_cookie


def _capture_navigation_passthrough(
    response,
    page,
    requested_url: str,
    max_size: int | None,
) -> "CapturedResponse | None":
    """Validate and capture a challenge-free main-document GET response."""

    if response is None:
        return None
    try:
        status = int(response.status)
        response_url = str(response.url)
        page_url = str(page.url)
        requested = urlparse(requested_url)
        final_response = urlparse(response_url)
        final_page = urlparse(page_url)
        requested_network_identity = _network_url_identity(requested)
        response_network_identity = _network_url_identity(final_response)
        response_document_identity = _origin_path_identity(final_response)
        page_document_identity = _origin_path_identity(final_page)
    except (TypeError, ValueError):
        return None

    if not 200 <= status < 300:
        return None
    if (
        requested.scheme not in {"http", "https"}
        or final_response.scheme != requested.scheme
        or final_page.scheme != requested.scheme
        or registrable_domain(requested.hostname or "")
        != registrable_domain(final_response.hostname or "")
        or registrable_domain(requested.hostname or "")
        != registrable_domain(final_page.hostname or "")
    ):
        return None

    # Chromium follows server redirects inside page.goto(). Wafer cannot return
    # that final 2xx without either violating follow_redirects=False or losing
    # redirect history. Fail closed and leave redirects to the normal transport.
    if requested_network_identity != response_network_identity:
        return None

    # goto() returns the final server-redirect response. Reject a different
    # document after Cloudflare's grace window, but tolerate query/fragment-only
    # history.replaceState() cleanup on the document that actually produced the
    # captured response.
    if response_document_identity != page_document_identity:
        return None

    lowered_url = page_url.lower()
    if "invitation" in lowered_url or "siteclosed" in lowered_url:
        return None

    headers, set_cookie = _response_headers(response)
    content_type = headers.get("content-type", "").lower()
    disposition = headers.get("content-disposition", "").lower()
    if (
        not (
            content_type.startswith("text/html")
            or content_type.startswith("application/xhtml+xml")
        )
        or "attachment" in disposition
    ):
        return None

    try:
        body = response.body()
    except Exception:
        return None
    if not isinstance(body, bytes):
        return None
    if max_size is not None and len(body) > max_size:
        raise ResponseTooLarge(response_url, len(body), max_size)
    if not body:
        return None
    html = body.decode("utf-8", errors="replace")
    if _is_cloudflare_absent_challenge_html(html):
        return None

    return CapturedResponse(
        url=response_url,
        status=status,
        headers=headers,
        body=body,
        set_cookie=set_cookie,
    )


def _capture_tmd_browser_passthrough(
    response,
    page,
    requested_url: str,
    max_size: int | None,
) -> "CapturedResponse | None":
    """Capture a challenge-free TMD application document from Chrome.

    This is deliberately not transport clearance. Alibaba can finish a browser
    navigation without minting a transferable ``x5sec``; in that case wafer
    may return the validated browser document for this GET, but must not claim
    that a subsequent wreq replay is unlocked.
    """

    try:
        requested = urlparse(requested_url)
        page_url = str(page.url)
        current = urlparse(page_url)
        if (
            requested.scheme not in {"http", "https"}
            or _network_url_identity(requested) != _network_url_identity(current)
        ):
            return None
    except (TypeError, ValueError):
        return None

    status = 200
    matched_response = None
    if response is not None:
        try:
            response_url = urlparse(str(response.url))
            if _network_url_identity(response_url) == _network_url_identity(current):
                status = int(response.status)
                matched_response = response
        except (TypeError, ValueError):
            status = 200
    if not 200 <= status < 300:
        return None

    lowered_url = page_url.lower()
    if "invitation" in lowered_url or "siteclosed" in lowered_url:
        return None

    try:
        html = page.content()
    except Exception:
        return None
    if not isinstance(html, str) or not html:
        return None
    body = html.encode("utf-8")
    if max_size is not None and len(body) > max_size:
        raise ResponseTooLarge(page_url, len(body), max_size)

    from wafer._challenge import detect_challenge

    headers, set_cookie = _rendered_headers(matched_response)
    if (
        detect_challenge(status, headers, html, url=page_url) is not None
        or _is_passthrough_challenge_html(html)
    ):
        return None

    return CapturedResponse(
        url=page_url,
        status=status,
        headers=headers,
        body=body,
        set_cookie=set_cookie,
    )


# How long to wait for TMD's x5sec cookie after a solved widget. It appears
# within milliseconds when the host mints one at all; a host that clears by
# navigation never does, and this bound is what keeps that case from consuming
# the whole solve budget.
_TMD_CLEARANCE_POLL_SECONDS = 8.0

_TMD_MTOP_RETRY_URL = "https://acs.aliexpress.com/h5/mtop.aliexpress.pdp.pc.query/1.0/"

# AliExpress MTop gateway hosts that issue callback-less punishments for their
# own endpoints: ``acs`` and ``recom-acs`` were seen live (2026-10-05). A
# storefront, seller or user-content subdomain is not a gateway.
_TMD_MTOP_GATEWAY_RE = re.compile(r"^(?:[a-z0-9-]+-)?acs\.aliexpress\.com$")

# Human slide envelope, measured on the live Alibaba Baxia widget
# (2026-07-31): a slide accepted by the SDK crossed the 258px track in 0.764s
# emitting 34 pointermoves, i.e. 421px/s at 44 events/s. These bracket that
# observation and are applied to the pressed phase of a slide replay only.
_SLIDE_DRAG_SECONDS = (0.62, 1.05)
_SLIDE_EVENT_RATE = (38.0, 58.0)


def _tmd_retry_target(challenge_url: str) -> str | None:
    """Return the exact application URL that a TMD cookie must unlock.

    BrowserSolver is normally called with the application URL whose 200 body
    contains the TMD redirect, not with the eventual ACS punishment URL.  In
    that case the immutable application URL is itself the retry target.

    When a caller does supply an ACS punishment URL, AliExpress retries its
    native MTop endpoint and Alibaba retries the strict callback embedded in
    that issued URL.

    MTop's own reCAPTCHA punishments carry no callback at all
    (``/h5/<api>/<version>/_____tmd_____/punish?x5secdata=..&x5step=2&
    action=captcharecaptcha``, observed 2026-10-05). Their path names the
    exact endpoint that was refused, so that endpoint on the AliExpress host
    that issued it (``acs`` or ``recom-acs`` live) is the retry target.
    Without it the solved widget's fresh x5sec was never looked for and every
    such solve was reported as a failure. Any other punishment URL with no
    safe same-family callback still fails closed: one that carries a callback
    the strict parser rejects, one from a host that is not an MTop gateway,
    and every callback-less Alibaba one.
    """

    # Reuse Baxia's single strict parser so callback validation cannot drift
    # between the inner drag evidence and this outer replay-scope gate.
    from wafer.browser._drag import (
        _BAXIA_CALLBACK_KEYS,
        _BAXIA_HOSTNAME_RE,
        _baxia_punish_mtop_endpoint,
        _expected_baxia_callback,
        _expected_baxia_punish_path,
    )

    try:
        parsed = urlparse(challenge_url)
        port = parsed.port
    except (TypeError, ValueError):
        return None
    host = (parsed.hostname or "").lower()
    if (
        parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or port not in (None, 443)
        or not _BAXIA_HOSTNAME_RE.fullmatch(host)
    ):
        return None
    if host == "aliexpress.com" or host.endswith(".aliexpress.com"):
        family = "aliexpress.com"
    elif host == "alibaba.com" or host.endswith(".alibaba.com"):
        family = "alibaba.com"
    else:
        return None

    is_punishment = _expected_baxia_punish_path(parsed.path, family)
    if not is_punishment:
        native_mtop = urlparse(_TMD_MTOP_RETRY_URL)
        if (
            family == "aliexpress.com"
            and host == (native_mtop.hostname or "")
            and parsed.path == native_mtop.path
        ):
            return parsed._replace(fragment="").geturl()
        # ACS is challenge infrastructure, never an application retry target.
        # A non-punishment ACS URL cannot prove that a cookie unlocks the
        # caller's Alibaba/AliExpress operation.
        if host in {"acs.alibaba.com", "acs.aliexpress.com"}:
            return None
        return parsed._replace(fragment="").geturl()

    callback = _expected_baxia_callback(challenge_url)
    if callback is None:
        offered = parse_qs(parsed.query, keep_blank_values=True)
        if (
            family == "aliexpress.com"
            and _TMD_MTOP_GATEWAY_RE.fullmatch(host)
            and not any(key in offered for key in _BAXIA_CALLBACK_KEYS)
        ):
            endpoint = _baxia_punish_mtop_endpoint(parsed.path, family)
            if endpoint is not None:
                api, version = endpoint
                return f"https://{host}/h5/{api}/{version}/"
        return None
    callback_host = (urlparse(callback).hostname or "").lower()
    if not (callback_host == family or callback_host.endswith(f".{family}")):
        return None
    if family == "aliexpress.com":
        return _TMD_MTOP_RETRY_URL
    return callback


def _tmd_recaptcha_frame_present(page) -> bool:
    """Whether any frame is an issued TMD punishment selecting reCAPTCHA.

    Only a vendor-issued punishment URL is trusted: HTTPS on an Alibaba or
    AliExpress host, with a path the strict Baxia parser accepts. A Google
    frame alone never counts (a page may embed an unrelated widget), and
    neither does a lookalike ``/_____tmd_____/punish`` on any other host, such
    as an ad or user-content iframe.
    """

    from wafer._base import _tmd_is_recaptcha_challenge
    from wafer.browser._drag import (
        _baxia_family,
        _expected_baxia_punish_path,
        _safe_baxia_target,
    )

    try:
        frames = list(page.frames)
    except Exception:
        return False
    for frame in frames:
        try:
            url = frame.url
        except Exception:
            continue
        if not isinstance(url, str):
            continue
        target = _safe_baxia_target(url)
        if target is None:
            continue
        family = _baxia_family((target.hostname or "").lower())
        if (
            family is not None
            and _expected_baxia_punish_path(target.path, family)
            and _tmd_is_recaptcha_challenge(url)
        ):
            return True
    return False


def _tmd_cookie_applies(cookie: dict, retry_url: str = _TMD_MTOP_RETRY_URL) -> bool:
    """Apply browser cookie scope rules to an exact application retry."""

    try:
        target = urlparse(retry_url)
        host = (target.hostname or "").lower()
        request_path = target.path or "/"
        domain = str(cookie.get("domain", ""))
        path = str(cookie.get("path", "/")) or "/"
        expires = cookie.get("expires", cookie.get("expirationDate", 0))
        expiry = float(expires) if expires not in (None, "") else 0.0
    except (TypeError, ValueError):
        return False
    if not domain or not browser_cookie_matches_host(domain, host):
        return False
    if not request_path.startswith(path):
        return False
    if not path.endswith("/") and len(request_path) > len(path):
        if request_path[len(path)] != "/":
            return False
    # Playwright reports non-persistent session cookies as -1/0. Positive
    # timestamps are Unix seconds and must still cover the retry.
    return expiry <= 0 or expiry > time.time()


def _has_tmd_x5sec_clearance(
    cookies: list[dict], retry_url: str = _TMD_MTOP_RETRY_URL
) -> bool:
    """Require x5sec scoped to the exact native MTop retry URL."""

    return any(
        cookie.get("name") == "x5sec"
        and isinstance(cookie.get("value"), str)
        and bool(cookie["value"])
        and _tmd_cookie_applies(cookie, retry_url)
        for cookie in cookies
    )


def _tmd_x5sec_signatures(
    cookies: list[dict], retry_url: str = _TMD_MTOP_RETRY_URL
) -> set[tuple[str, str, str]]:
    """Internal x5sec identity set; values are never logged."""

    signatures: set[tuple[str, str, str]] = set()
    for cookie in cookies:
        if cookie.get("name") != "x5sec":
            continue
        value = cookie.get("value")
        if not isinstance(value, str) or not value:
            continue
        if _tmd_cookie_applies(cookie, retry_url):
            domain = str(cookie.get("domain", "")).lstrip(".").lower()
            path = str(cookie.get("path", "/")) or "/"
            signatures.add((domain, path, value))
    return signatures


def _valid_proxy_url(value: str) -> bool:
    if (
        not isinstance(value, str)
        or not value
        or any(ord(char) <= 0x20 or ord(char) == 0x7F for char in value)
    ):
        return False
    try:
        parsed = urlparse(value)
        port = parsed.port
    except (TypeError, ValueError):
        return False
    return (
        parsed.scheme in {"http", "https", "socks5"}
        and bool(parsed.hostname)
        and port not in {None, 0}
        and parsed.path in {"", "/"}
        and not parsed.params
        and not parsed.query
        and not parsed.fragment
    )


def _valid_egress_guard_url(value: str) -> bool:
    """A browser-only guard must be an unauthenticated loopback SOCKS5 hop."""

    if not _valid_proxy_url(value):
        return False
    parsed = urlparse(value)
    if (
        parsed.scheme != "socks5"
        or parsed.username is not None
        or parsed.password is not None
    ):
        return False
    try:
        return ipaddress.ip_address(parsed.hostname or "").is_loopback
    except ValueError:
        return False


def _proxy_identity(value: str) -> tuple[str, str, int, str | None, str | None]:
    """Canonical fields used to compare proxy configurations safely."""

    parsed = urlparse(value)
    return (
        parsed.scheme.lower(),
        (parsed.hostname or "").rstrip(".").lower(),
        parsed.port or 0,
        unquote(parsed.username) if parsed.username is not None else None,
        unquote(parsed.password) if parsed.password is not None else None,
    )


def _playwright_proxy(value: str) -> dict[str, str]:
    """Convert a validated proxy URL to Playwright's structured shape."""

    scheme, host, port, username, password = _proxy_identity(value)
    display_host = f"[{host}]" if ":" in host else host
    proxy = {"server": f"{scheme}://{display_host}:{port}"}
    if username is not None:
        proxy["username"] = username
    if password is not None:
        proxy["password"] = password
    return proxy


# ---------------------------------------------------------------------------
# Stealth: no JS injection needed.
#
# The ``--disable-blink-features=AutomationControlled`` launch flag
# makes ``navigator.webdriver`` return ``false`` via a native getter
# (``[native code]``).  Real system Chrome headful provides native
# plugins, WebGL, permissions, chrome.csi/loadTimes, and voices.
#
# Previous approach: injected JS overrides via route interception or
# CDP.  This was actively harmful because:
# - navigator.webdriver override replaced a native getter with an
#   arrow function detectable via ``toString()``
# - chrome.runtime stub had only 2 keys + non-native functions
# - speechSynthesis.getVoices wrapper leaked source in toString()
# - Route interception broke WAF iframes (DataDome WASM PoW)
#
# If a future Chrome/Patchright change breaks native stealth, use
# CDP ``Page.addScriptToEvaluateOnNewDocument`` (requires
# ``Page.enable`` first, do NOT detach the session).
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Headless fingerprint patch (macOS)
#
# Headless Chrome on macOS leaks 6 properties that WAFs detect from
# cross-origin iframes (e.g. DataDome's geo.captcha-delivery.com):
#   colorDepth/pixelDepth: 24 (should be 30 on Retina)
#   outerWidth: == innerWidth (should be +2 for window chrome)
#   outerHeight: == innerHeight (should be +80 for title/tab/toolbar)
#   screenY/screenTop: ~22 (should be ~56 with menu bar)
#
# Every frame of a real window reports the same screen, colorDepth and
# outer size: an iframe's outerWidth is the window's, not the iframe's.
# Headless iframes report their own values instead (colorDepth 24, screen
# 800x600 under a 2560x1440 top document, measured on Chrome 154), so the
# per-page hardening computes one geometry from the viewport and injects it
# into the page and every out-of-process iframe alike.
#
# ``__GEOMETRY__`` is that geometry, or ``null`` to derive it from the
# window the script runs in, which is only meaningful in a top-level
# document. The derived form keeps the headless-signature guard
# (outerWidth === innerWidth); the fixed form cannot use it, because an
# iframe's native outerWidth is the window's and so always exceeds its
# innerWidth. It skips a document it has already patched instead.
# ---------------------------------------------------------------------------

# Common macOS displays in CSS pixels at default scaling. The screen patch
# picks the first that fits the viewport with room for window chrome.
_MAC_DISPLAYS = (
    (1440, 900),
    (1512, 982),
    (1710, 1107),
    (1728, 1117),
    (2560, 1440),
)
# What a fitted display leaves above the viewport: title bar, tabs, toolbar.
_MAC_CHROME_HEIGHT = 120

_HEADLESS_FIX_TEMPLATE = r"""(function () {
  var isMac = navigator.platform === 'MacIntel' ||
    navigator.userAgent.indexOf('Mac OS X') !== -1;
  if (!isMac) return;
  var g = __GEOMETRY__;
  if (g === null) {
    // In headed mode outerWidth > innerWidth (window chrome adds ~2px).
    // In headless, outerWidth === innerWidth OR 0 (early document load
    // during cross-origin navigation).  Skip only when > innerWidth.
    if (window.outerWidth > window.innerWidth) return;
    // Screen dimensions: headless reports viewport == screen which is
    // impossible on a real display.  Pick a plausible macOS resolution
    // that fits the viewport.
    var displays = __DISPLAYS__;
    var vw = window.innerWidth, vh = window.innerHeight;
    var sw = 2560, sh = 1440;
    for (var i = 0; i < displays.length; i++) {
      if (displays[i][0] > vw && displays[i][1] > vh + __CHROME_HEIGHT__) {
        sw = displays[i][0]; sh = displays[i][1]; break;
      }
    }
    g = {screenWidth: sw, screenHeight: sh,
         outerWidth: function () { return window.innerWidth + 2; },
         outerHeight: function () { return window.innerHeight + 80; }};
  } else if (screen.colorDepth === 30 && screen.width === g.screenWidth &&
             window.outerWidth === g.outerWidth) {
    return;
  }
  var _ts = Function.prototype.toString;
  var _m = new Map();
  var _nts = function () {
    return _m.has(this) ? _m.get(this) : _ts.call(this);
  };
  Object.defineProperty(_nts, 'name', {value: 'toString'});
  Object.defineProperty(_nts, 'length', {value: 0});
  Function.prototype.toString = _nts;
  _m.set(_nts, 'function toString() { [native code] }');
  function patch(obj, prop, val) {
    var orig = Object.getOwnPropertyDescriptor(obj, prop);
    if (!orig || !orig.get) return;
    var g = typeof val === 'function' ? val : function () { return val; };
    Object.defineProperty(g, 'name', {value: orig.get.name});
    var desc = {get: g, enumerable: orig.enumerable, configurable: true};
    if (orig.set) desc.set = orig.set;
    Object.defineProperty(obj, prop, desc);
    _m.set(g, _ts.call(orig.get));
  }
  // screen.colorDepth/pixelDepth: headless reports 24 (8-bit), real
  // macOS is 30 (10-bit).  Safe to patch because --force-color-profile=
  // scrgb-linear makes the CSS media queries match (color:10 = true,
  // dynamic-range:high = true), so there's no cross-check inconsistency.
  patch(Screen.prototype, 'colorDepth', 30);
  patch(Screen.prototype, 'pixelDepth', 30);
  patch(window, 'outerWidth', g.outerWidth);
  patch(window, 'outerHeight', g.outerHeight);
  patch(window, 'screenY', 56);
  patch(window, 'screenTop', 56);
  var menuBar = 37;
  patch(Screen.prototype, 'width', g.screenWidth);
  patch(Screen.prototype, 'height', g.screenHeight);
  patch(Screen.prototype, 'availWidth', g.screenWidth);
  patch(Screen.prototype, 'availHeight', g.screenHeight - menuBar);
  patch(Screen.prototype, 'availTop', menuBar);
  patch(Screen.prototype, 'availLeft', 0);
})();"""


def _headless_geometry(viewport_width: int, viewport_height: int) -> dict:
    """The window and screen a headless page of this viewport reports."""
    screen_width, screen_height = _MAC_DISPLAYS[-1]
    for width, height in _MAC_DISPLAYS:
        if width > viewport_width and height > viewport_height + _MAC_CHROME_HEIGHT:
            screen_width, screen_height = width, height
            break
    return {
        "screenWidth": screen_width,
        "screenHeight": screen_height,
        "outerWidth": viewport_width + 2,
        "outerHeight": viewport_height + 80,
    }


def _headless_fix_script(geometry: dict | None = None) -> str:
    """The macOS headless window fix, with *geometry* fixed or derived."""
    return (
        _HEADLESS_FIX_TEMPLATE.replace(
            "__GEOMETRY__", "null" if geometry is None else json.dumps(geometry)
        )
        .replace("__DISPLAYS__", json.dumps([list(d) for d in _MAC_DISPLAYS]))
        .replace("__CHROME_HEIGHT__", str(_MAC_CHROME_HEIGHT))
    )


_HEADLESS_FIX_SCRIPT = _headless_fix_script()


# ---------------------------------------------------------------------------
# screenX/screenY fix for CDP Input.dispatchMouseEvent
#
# Chromium bug #40280325: CDP mouse events set screenX=clientX and
# screenY=clientY instead of adding the window position offset.
# WAFs (esp. DataDome) compare screenX/Y vs clientX/Y to detect
# CDP-dispatched events.  This script patches the getters so they
# add the window position when the bug is detected (val == clientXY).
#
# Previously shipped as an MV3 extension, but extensions don't load
# in Playwright's new_context() (incognito-like).  Now injected via
# CDP Page.addScriptToEvaluateOnNewDocument into the page and, through
# auto-attach on the page's session, into every out-of-process iframe
# before its document runs.
# ---------------------------------------------------------------------------
_SCREENXY_FIX_SCRIPT = r"""(function () {
  var origSX = Object.getOwnPropertyDescriptor(MouseEvent.prototype, 'screenX');
  var origSY = Object.getOwnPropertyDescriptor(MouseEvent.prototype, 'screenY');
  if (!origSX || !origSY) return;
  // Already replaced in this document (the init script ran and the navigation
  // fallback is re-applying it): wrapping twice can leave PointerEvent
  // half-patched.
  if (Function.prototype.toString.call(origSX.get).indexOf('[native code]') === -1)
    return;
  [MouseEvent, PointerEvent].forEach(function (cls) {
    Object.defineProperty(cls.prototype, 'screenX', {
      get: function () {
        var val = origSX.get.call(this);
        if (val === this.clientX) return val + (window.screenX || 0);
        return val;
      }
    });
    Object.defineProperty(cls.prototype, 'screenY', {
      get: function () {
        var val = origSY.get.call(this);
        if (val === this.clientY)
          return val + (window.screenY || 0)
            + (window.outerHeight - window.innerHeight);
        return val;
      }
    });
  });
})();"""


# ---------------------------------------------------------------------------
# Recording helpers (module-level, shared by all BrowserSolver instances)
# ---------------------------------------------------------------------------

# Direction -> approximate angle (radians) for atan2(dy, dx) from start->target.
# Used as fallback when metadata lacks start/end coordinates.
_DIRECTION_ANGLES: dict[str, float] = {
    "to_center_from_ul": 0.57,  # down-right
    "to_center_from_ur": 2.55,  # down-left
    "to_center_from_l": 0.12,  # right, slightly down
    "to_center_from_bl": -0.40,  # up-right
    "to_center_from_br": -2.72,  # up-left
    "to_lower_from_ul": 0.85,  # steep down-right
}


def _parse_metadata(line: str) -> dict[str, str]:
    """Parse a ``# key=val key=val`` metadata comment line."""
    meta: dict[str, str] = {}
    if not line.startswith("#"):
        return meta
    for token in line[1:].strip().split():
        if "=" in token:
            k, v = token.split("=", 1)
            meta[k] = v
    return meta


def _parse_csv_rows(text: str, fields: tuple[str, ...]) -> list[dict[str, float]]:
    """Parse CSV text (skipping ``#`` comment lines) into a list of dicts."""
    clean = "\n".join(line for line in text.splitlines() if not line.startswith("#"))
    rows: list[dict[str, float]] = []
    reader = csv.DictReader(io.StringIO(clean))
    for row in reader:
        rows.append({f: float(row[f]) for f in fields})
    return rows


def _angle_from_metadata(meta: dict[str, str]) -> float:
    """Compute approach angle from path metadata start/end coordinates."""
    try:
        sx, sy = (int(v) for v in meta["start"].split(","))
        ex, ey = (int(v) for v in meta["end"].split(","))
        return math.atan2(ey - sy, ex - sx)
    except (KeyError, ValueError):
        pass
    # Fallback: infer from direction name
    direction = meta.get("direction", "")
    return _DIRECTION_ANGLES.get(direction, 0.6)


# Realistic viewport sizes (width, height) weighted toward common resolutions
_VIEWPORTS = [
    (1920, 1080),
    (1366, 768),
    (1536, 864),
    (1440, 900),
    (1280, 720),
]


_DRIVER_PRELOAD = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "_driver_preload.js"
)
# NODE_OPTIONS is process-wide; one driver start at a time edits it.
_DRIVER_ENV_LOCK = threading.RLock()


# wafer's user-agent override per browser user agent, for the driver preload:
# it gives the override to the pages Playwright sets up itself, popups
# included, before they run (see _driver_preload.js).
_UA_TABLE: dict[str, dict] = {}
_UA_FILE: list[str] = []
_UA_LOCK = threading.Lock()


def _remove_quietly(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


def _ua_params_file() -> str:
    """This process's override file, created private on first use."""
    with _UA_LOCK:
        if not _UA_FILE:
            fd, path = tempfile.mkstemp(prefix="wafer-ua-", suffix=".json")
            with os.fdopen(fd, "w") as handle:
                handle.write("{}")
            atexit.register(_remove_quietly, path)
            _UA_FILE.append(path)
        return _UA_FILE[0]


def _publish_ua_override(browser_user_agent: str | None, params: dict | None) -> None:
    """Make *params* the override the driver gives this browser's new pages."""
    if not browser_user_agent or not params:
        return
    path = _ua_params_file()
    with _UA_LOCK:
        if _UA_TABLE.get(browser_user_agent) == params:
            return
        _UA_TABLE[browser_user_agent] = params
        fd, staged = tempfile.mkstemp(
            prefix="wafer-ua-", suffix=".json", dir=os.path.dirname(path)
        )
        try:
            with os.fdopen(fd, "w") as handle:
                json.dump(_UA_TABLE, handle)
            os.replace(staged, path)
        except OSError:
            _remove_quietly(staged)
            logger.debug("Could not publish the user-agent override", exc_info=True)


@contextlib.contextmanager
def hardened_driver_env():
    """Start Patchright's driver inside this block to leave shared workers to wafer.

    Playwright pauses every new shared worker and resumes it at once, and
    Chromium delivers that resume ahead of wafer's override, so a shared
    worker could run its first script with the launch's empty high-entropy
    client hints (15-17 of 100 for a ``blob:`` worker, measured on a real
    sensor). Inside this block the driver is started with a preload
    (``_driver_preload.js``) that keeps its browser session from attaching
    shared workers, so :func:`harden_page` resumes each one only after its
    override is in: 0 of 100. Wrap only the start::

        with hardened_driver_env():
            playwright = sync_playwright().start()

    The preload also gives :func:`harden_page`'s user-agent override to the
    pages the driver sets up itself, popups included, before they run (their
    first document read the launch's empty high-entropy client hints, 3 of 3).
    harden_page publishes it in a private per-process file named by
    ``WAFER_UA_PARAMS``.

    It appends to ``NODE_OPTIONS`` and sets ``WAFER_UA_PARAMS`` for the
    duration and restores both after; they are process-wide, so node
    processes other threads start in that window get them too (the preload
    changes nothing but a Playwright driver's shared-worker auto-attach and
    its empty per-page user-agent override).
    """
    escaped = _DRIVER_PRELOAD.replace("\\", "\\\\").replace('"', '\\"')
    option = f'--require "{escaped}"'
    params_file = _ua_params_file()
    with _DRIVER_ENV_LOCK:
        previous = os.environ.get("NODE_OPTIONS")
        previous_params = os.environ.get("WAFER_UA_PARAMS")
        os.environ["NODE_OPTIONS"] = f"{previous} {option}" if previous else option
        os.environ["WAFER_UA_PARAMS"] = params_file
        try:
            yield
        finally:
            for name, value in (
                ("NODE_OPTIONS", previous),
                ("WAFER_UA_PARAMS", previous_params),
            ):
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value


@dataclass(frozen=True)
class _MacScreen:
    """The main display, in points, as headed Chrome reports it."""

    width: int
    height: int
    # Work-area insets: the menu bar above, the Dock wherever it sits.
    top: int
    bottom: int
    left: int
    right: int
    scale: int
    color_depth: int


# Used when AppKit cannot be asked (no window server): a 14-inch MacBook Pro
# with its Dock hidden.
_DEFAULT_MAC_SCREEN = _MacScreen(1512, 982, 34, 0, 0, 0, 2, 30)

# NSScreen, through JavaScript for Automation: the frame, the visible frame
# (bottom-left origin, so its y is the Dock's height when the Dock is below),
# the backing scale, and whether the display covers P3. Chrome reports a P3
# display as colorDepth 30 and any other as 24.
_SCREEN_QUERY = (
    'ObjC.import("AppKit");'
    "var s = $.NSScreen.mainScreen;"
    "var f = s.frame, v = s.visibleFrame;"
    "JSON.stringify([f.size.width, f.size.height, v.origin.x, v.origin.y,"
    " v.size.width, v.size.height, s.backingScaleFactor,"
    " s.canRepresentDisplayGamut($.NSDisplayGamutP3)])"
)
_HOST_SCREEN: list = []
_HOST_SCREEN_LOCK = threading.Lock()

# What Chrome 154 on macOS draws above the page: tab strip and toolbar.
# Headed reports outerHeight - innerHeight = 87, and headless reports the same
# for a window sized with --window-size (measured 2026-10-06).
_MAC_TOOLBAR_HEIGHT = 87


def _parse_mac_screen(output: str) -> "_MacScreen | None":
    try:
        width, height, vx, vy, vw, vh, scale, p3 = json.loads(output)
        width, height = round(width), round(height)
        vx, vy, vw, vh = round(vx), round(vy), round(vw), round(vh)
        screen = _MacScreen(
            width=width,
            height=height,
            top=height - (vy + vh),
            bottom=vy,
            left=vx,
            right=width - (vx + vw),
            scale=max(1, round(scale)),
            color_depth=30 if p3 else 24,
        )
    except (TypeError, ValueError):
        return None
    insets = (screen.top, screen.bottom, screen.left, screen.right)
    if width <= 0 or height <= 0 or min(insets) < 0:
        return None
    return screen


def _host_screen() -> "_MacScreen":
    """The Mac's main display, asked once per process; a default without one."""
    with _HOST_SCREEN_LOCK:
        if _HOST_SCREEN:
            return _HOST_SCREEN[0]
        screen = None
        try:
            result = subprocess.run(
                ["osascript", "-l", "JavaScript", "-e", _SCREEN_QUERY],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                screen = _parse_mac_screen(result.stdout.strip())
        except (OSError, subprocess.SubprocessError):
            pass
        if screen is None:
            logger.debug("Could not read the main display; using a default")
            screen = _DEFAULT_MAC_SCREEN
        _HOST_SCREEN.append(screen)
        return screen


def _screen_info_switch(screen: "_MacScreen") -> str:
    """``--screen-info`` for *screen*: bounds and insets in device pixels."""
    s = screen.scale
    return (
        f"--screen-info={{0,0 {screen.width * s}x{screen.height * s} "
        f"colorDepth={screen.color_depth} "
        f"workAreaTop={screen.top * s} workAreaBottom={screen.bottom * s} "
        f"workAreaLeft={screen.left * s} workAreaRight={screen.right * s}}}"
    )


def _fitting_viewports(screen: "_MacScreen") -> list[tuple[int, int]]:
    """The viewports whose window fits *screen*'s work area."""
    width = screen.width - screen.left - screen.right
    height = screen.height - screen.top - screen.bottom
    return [
        (w, h)
        for w, h in _VIEWPORTS
        if w <= width and h + _MAC_TOOLBAR_HEIGHT <= height
    ]


def _default_viewport(screen: "_MacScreen") -> tuple[int, int]:
    fitting = _fitting_viewports(screen)
    if fitting:
        return max(fitting, key=lambda v: v[0] * v[1])
    return (
        screen.width - screen.left - screen.right,
        screen.height - screen.top - screen.bottom - _MAC_TOOLBAR_HEIGHT,
    )


@dataclass(frozen=True)
class HardenedLaunch:
    """Chromium launch settings that keep an automated browser unremarkable.

    ``args`` and ``ignore_default_args`` go straight to Playwright's
    ``chromium.launch`` or ``launch_persistent_context``.

    ``init_scripts`` are registered per page through CDP
    ``Page.addScriptToEvaluateOnNewDocument``, which needs ``Page.enable``
    first and must not have its CDP session detached afterwards -detaching
    unregisters them. Superseded by :func:`harden_page`, which registers them
    itself with one window geometry for the page and its iframes; these derive
    the geometry from their own window, which is only right in a top-level
    document. Kept for callers that already register them.
    """

    args: tuple[str, ...]
    ignore_default_args: tuple[str, ...]
    init_scripts: tuple[str, ...]


def hardened_launch_config(
    *,
    headless: bool,
    proxied: bool = False,
    platform: str | None = None,
    user_agent: str | None = None,
    viewport: tuple[int, int] | None = None,
) -> HardenedLaunch:
    """The launch settings wafer's own solver browser uses.

    Exposed for callers that drive their own Playwright because they need the
    exchange log rather than a settled document, which :meth:`BrowserSolver.render`
    cannot give them. The alternative is reimplementing this set, and drift is
    silent in the worst way: a site that answers a flagged browser differently
    gets recorded as a fact about the site rather than about the browser.

    ``proxied`` mirrors wafer's own rule of disabling page-controlled UDP only
    when a proxy is configured, so a direct browser's launch fingerprint stays
    unchanged. ``platform`` defaults to :data:`sys.platform`; pass it to build
    another host's configuration, which is also how this gets tested off-target.

    ``user_agent`` matters only when ``headless``. Chrome puts ``HeadlessChrome``
    in its own user agent whenever the ``--headless`` switch is present, and
    that default reaches every target nothing overrides before it runs: a
    service worker's script fetch and ``navigator.userAgent``, and everything
    a shared worker does. Passing the browser's own user agent, scrubbed with
    :func:`scrub_headless_ua`, adds ``--user-agent`` so no target falls back to
    it. Read it from a first launch rather than composing one, so the version
    stays truthful. Chrome then sends only low-entropy client hints by
    default; :func:`harden_page` restores the full set on every page, iframe
    and worker it can reach. Headed Chrome needs neither.

    This requires a full Chrome (``channel="chrome"`` or ``executable_path``).
    Playwright's default ``headless=True`` binary is chrome-headless-shell,
    which ignores ``--headless=new`` and brands its workers ``HeadlessChrome``.

    The CDP screenX/screenY compatibility patch is deliberately absent. It is
    only correct on a Chrome whose event descriptors are already wrong, which
    wafer establishes with a real-input probe at solve time; applying it
    unconditionally double-counts the window offset on a native-correct build.

    Headless on macOS, the launch also describes the Mac's real main display
    to Chrome (``--screen-info``: size, menu bar and Dock, P3 color depth;
    ``--force-device-scale-factor``: its backing scale) and opens a window of
    ``viewport`` plus the toolbar (``--window-size``). In a context created
    with ``no_viewport=True`` every frame then reports exactly what headed
    Chrome on that Mac does, natively: screen, available area, colorDepth,
    devicePixelRatio, and an outer window the toolbar's height taller than the
    page, so :func:`harden_page` needs no window script. ``viewport`` defaults
    to the largest common size whose window fits the display's work area.
    """
    host = sys.platform if platform is None else platform
    args = [
        "--disable-blink-features=AutomationControlled",
        "--enable-gpu",
        # Branded Chrome wakes Google Updater 19s after launch, and the
        # updater inherits the stdio pipes Playwright waits on, so any close
        # after that point took 17-26s on macOS (Chromium issue 481087595).
        # Browser-process only: nothing about it is visible to a page.
        "--disable-updater-scheduler",
    ]
    if host == "linux":
        # Pin ANGLE to Mesa's OpenGL backend. Its automatic Linux backend
        # selection can resolve to ``gl=none`` under Xvfb, making WebGL
        # disappear entirely even though the image includes Mesa DRI.
        args.extend(
            [
                "--use-gl=angle",
                "--use-angle=gl",
                "--ignore-gpu-blocklist",
            ]
        )
    else:
        args.append("--use-gl=angle")
    if proxied:
        # The configured proxy is TCP-only. Disable page-controlled UDP paths
        # that could otherwise bypass it.
        args.extend(
            [
                "--disable-quic",
                "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
            ]
        )
    if host == "darwin":
        args.append("--use-angle=metal")

    ignored = [
        # --enable-automation: sets internal automation state,
        # removes chrome.runtime from window.chrome.
        "--enable-automation",
        # --force-color-profile=srgb: alters canvas fingerprint
        # (real Chrome uses system profile).
        "--force-color-profile=srgb",
    ]

    init_scripts = []
    if headless:
        # Use --headless=new (Chrome 112+) instead of the old --headless mode.
        # The new mode uses Chrome's real compositor pipeline, which gives full
        # performance.now timer resolution (old mode clamps to 100us - a known
        # timing-based detection signal).
        args.append("--headless=new")
        ignored.append("--headless")

        if host == "darwin":
            # Force scRGB-linear so the rendering pipeline reports 10-bit color
            # (color: 10) and HDR (dynamic-range: high). Without this, headless
            # Chrome on macOS reports 8-bit sRGB, and WAFs like Kasada
            # cross-check CSS computed styles against screen.colorDepth.
            args.append("--force-color-profile=scrgb-linear")
            # The Mac's backing scale for every frame. Playwright's
            # device_scale_factor reaches only the top frame, so without this a
            # cross-site iframe reports devicePixelRatio 1 under a top document
            # reporting 2, and an iframe nested back on the top document's site
            # (A->B->A) drags the top document to 1 too.
            # The real display when running on a Mac; a default when building
            # a macOS configuration elsewhere.
            screen = (
                _host_screen() if sys.platform == "darwin" else _DEFAULT_MAC_SCREEN
            )
            args.append(f"--force-device-scale-factor={screen.scale}")
            # The real display, natively: without it a headless page's screen
            # is its viewport, with no menu bar or Dock, and colorDepth is 24
            # where headed Chrome on a P3 Mac reports 30. A context with
            # no_viewport=True then needs no window script at all.
            args.append(_screen_info_switch(screen))
            width, height = viewport or _default_viewport(screen)
            args.append(f"--window-size={width},{height + _MAC_TOOLBAR_HEIGHT}")
        # Self-guarding: the script returns immediately unless it finds the
        # macOS headless signature, so registering it off-target is inert.
        init_scripts.append(_HEADLESS_FIX_SCRIPT)
        if user_agent:
            args.append(f"--user-agent={scrub_headless_ua(user_agent)}")
    elif host.startswith("linux"):
        # Headful browsers run under a real window manager. Start with the
        # conventional maximized desktop state so screen, outer-window, and
        # viewport geometry form one coherent envelope.
        args.append("--start-maximized")

    return HardenedLaunch(
        args=tuple(args),
        ignore_default_args=tuple(ignored),
        init_scripts=tuple(init_scripts),
    )


def scrub_headless_ua(user_agent: str) -> str:
    """Remove the ``HeadlessChrome`` token a headless build puts in its UA.

    Headless Chrome advertises ``HeadlessChrome/<version>`` where headed Chrome
    says ``Chrome/<version>``. Read the real value from a launched browser
    (``navigator.userAgent``) rather than composing one, so the version stays
    truthful, then apply this and pass the result to
    ``hardened_launch_config(user_agent=…)`` for the relaunch. Not to
    ``new_context(user_agent=…)``: Playwright attaches its own client-hint
    metadata to a context-level user agent.

    Returns the input unchanged when there is nothing to scrub.
    """
    if not user_agent:
        return user_agent
    return user_agent.replace("HeadlessChrome", "Chrome")


# For the launch that only reads the browser's own user agent. Launched
# without --user-agent, its background traffic carries HeadlessChrome: a
# Chrome network-time request to clients2.google.com went out through the
# configured proxy with that UA (measured 2026-10-06). It never needs the
# network, so it gets none: a proxy nothing listens on, and no background
# services.
_OFFLINE_ARGS = [
    "--proxy-server=http://127.0.0.1:9",
    "--proxy-bypass-list=<-loopback>",
    "--disable-background-networking",
]

# navigator.languages is ["en-US"] without this, where a real en-US Chrome
# reports ["en-US", "en"].
_ACCEPT_LANGUAGE = "en-US,en"

# Child targets are attached unflattened and paused until their overrides
# are in place. Flattened sessions cannot be addressed through Playwright's
# CDPSession, which has no way to route a message by sessionId.
_AUTO_ATTACH = (
    "Target.setAutoAttach",
    {"autoAttach": True, "waitForDebuggerOnStart": True, "flatten": False},
)

# How many levels of out-of-process iframes get hardened. Each level nests the
# message in one more JSON string, and escaping doubles the backslashes per
# level, so a message's size grows as 2**depth; a page nesting alternating
# cross-site iframes would otherwise make wafer build ever larger messages.
# Real pages rarely nest cross-site frames more than three deep. Frames below
# the cap are left to Chrome's own identity, not paused.
_MAX_CHILD_DEPTH = 4

# How long a child is held for its overrides to be acknowledged before wafer
# resumes it. An iframe is genuinely held until every auto-attached session
# resumes it, so this is what puts its scripts and UA in place before its
# document runs. (Workers are not held this way; see _SERVICE_WORKER_HOLD.)
_SETTLE_SECONDS = 1.0

# Bounds on bookkeeping a page can grow by churning frames or workers.
_MAX_PENDING_REPLIES = 256
_MAX_HANDLED_SHARED_WORKERS = 1024


def _ua_override_params(user_agent: str, browser_version: str | None) -> dict:
    """``setUserAgentOverride`` params with full client-hint metadata.

    The UA override always carries ``userAgentMetadata``. A user agent set any
    other way leaves Chrome to fill the metadata itself: chrome-headless-shell
    then brands every request ``HeadlessChrome``, and Playwright's
    ``new_context(user_agent=…)`` reports ``architecture: x86`` and
    ``platformVersion: 10.15.7`` on every macOS host, Apple Silicon included.
    Sending the override without any metadata drops ``sec-ch-ua`` entirely.
    """
    from wafer._fingerprint import cdp_ua_metadata

    params = cdp_ua_metadata(user_agent, browser_version=browser_version)
    params["acceptLanguage"] = _ACCEPT_LANGUAGE
    return params


def _color_gamut_command(headless: bool, host: str) -> list[tuple[str, dict]]:
    # --force-color-profile=scrgb-linear already makes (color: 10) and
    # (dynamic-range: high) match headed Chrome on macOS; color-gamut is the
    # one media feature it leaves behind.
    if headless and host == "darwin":
        return [
            (
                "Emulation.setEmulatedMedia",
                {"features": [{"name": "color-gamut", "value": "p3"}]},
            )
        ]
    return []


def _page_hardening_commands(
    *,
    headless: bool,
    ua_params: dict | None,
    scripts: tuple[str, ...] | list[str],
    platform: str | None = None,
) -> list[tuple[str, dict]]:
    """The CDP commands that harden one page, in the order they are sent.

    Shared by :func:`harden_page`, :func:`harden_page_async` and the solver, so
    the per-page half of the recipe has one source the same way the launch half
    does. *ua_params* comes from :func:`_ua_override_params`; ``None`` skips the
    override.
    """
    host = sys.platform if platform is None else platform
    commands: list[tuple[str, dict]] = [("Page.enable", {})]
    commands.extend(
        ("Page.addScriptToEvaluateOnNewDocument", {"source": source})
        for source in scripts
    )
    commands.extend(_color_gamut_command(headless, host))
    if ua_params:
        commands.append(("Emulation.setUserAgentOverride", ua_params))
    return commands


def _child_target_commands(
    target_type: str,
    *,
    headless: bool,
    ua_params: dict | None,
    scripts: tuple[str, ...] | list[str],
    platform: str | None = None,
    depth: int = 1,
) -> list[tuple[str, dict]]:
    """Commands for a target auto-attached under a hardened page.

    Sent while the target is paused, before ``Runtime.runIfWaitingForDebugger``.
    Without them a cross-site iframe takes the context-level user agent
    (or, with none, ``HeadlessChrome``), and its screen, colorDepth and outer
    size are its own rather than the window's. Workers inherit a frame's
    override but get the network one only from their own session, so a
    service worker's fetches would otherwise carry the browser default.

    Shared workers never attach under a page; :func:`_harden_shared_workers`
    sends them the worker commands from a browser session.

    An iframe gets exactly the page's commands, and attaches its own children
    in turn until *depth* reaches :data:`_MAX_CHILD_DEPTH`.
    """
    if target_type == "iframe":
        commands = _page_hardening_commands(
            headless=headless, ua_params=ua_params, scripts=scripts, platform=platform
        )
        if depth < _MAX_CHILD_DEPTH:
            commands.append(_AUTO_ATTACH)
        return commands
    if target_type in ("worker", "service_worker"):
        commands = []
        if ua_params:
            # Emulation first: it reaches the worker's own inspector, which is
            # what its navigator.userAgentData reads, and a service or shared
            # worker is racing it (see _harden_shared_workers).
            commands.append(("Emulation.setUserAgentOverride", ua_params))
            commands.append(("Network.setUserAgentOverride", ua_params))
        return commands
    return []


class _TargetRouter:
    """Addresses targets auto-attached, unflattened, under one CDP session.

    A child is a path of session ids from the root session. A message to it is
    nested in one ``Target.sendMessageToTarget`` per level; its events and
    replies come back nested in ``Target.receivedMessageFromTarget``.
    """

    def __init__(self) -> None:
        self._ids = itertools.count(1)
        self._pending: dict[int, str] = {}
        self._replied: dict[int, None] = {}
        # Sessions that detached; nothing they were sent will be answered.
        self.gone: dict[str, None] = {}
        # Id of the innermost message the latest wrap() built. Read it right
        # after wrap(), before anything that can yield to another handler.
        self.last_id = 0

    def wrap(
        self, path: tuple[str, ...], method: str, params: dict
    ) -> tuple[str, dict]:
        """The root-session command that delivers *method* to *path*."""
        message_id = next(self._ids)
        self.last_id = message_id
        self._pending[message_id] = method
        # Replies from a target that went away never arrive; keep the newest.
        while len(self._pending) > _MAX_PENDING_REPLIES:
            del self._pending[next(iter(self._pending))]
        message = {"id": message_id, "method": method, "params": params}
        for session_id in reversed(path[1:]):
            message = {
                "id": next(self._ids),
                "method": "Target.sendMessageToTarget",
                "params": {"sessionId": session_id, "message": json.dumps(message)},
            }
        return (
            "Target.sendMessageToTarget",
            {"sessionId": path[0], "message": json.dumps(message)},
        )

    def answered(self, message_id: int) -> bool:
        """Whether the reply to *message_id* (from :meth:`wrap`) has arrived.

        Only a recorded reply counts: an id dropped from the pending table to
        bound it was never answered.
        """
        return message_id in self._replied

    def _record(self, table: dict, key) -> None:
        table[key] = None
        while len(table) > _MAX_PENDING_REPLIES:
            del table[next(iter(table))]

    def unwrap(self, params: dict) -> tuple[tuple[str, ...], str | None, dict]:
        """Unnest a ``Target.receivedMessageFromTarget`` from the root session.

        Returns the path of the session that emitted it and, for an event, its
        method and params. A reply returns ``None`` for the method; a failed
        command is logged, since nothing waits on these replies.
        """
        path = (params["sessionId"],)
        message = json.loads(params["message"])
        while message.get("method") == "Target.receivedMessageFromTarget":
            inner = message.get("params") or {}
            path += (inner["sessionId"],)
            message = json.loads(inner["message"])
        if "method" in message:
            if message["method"] == "Target.detachedFromTarget":
                session_id = (message.get("params") or {}).get("sessionId")
                if session_id:
                    self._record(self.gone, session_id)
            return path, message["method"], message.get("params") or {}
        method = self._pending.pop(message.get("id"), None)
        if "id" in message:
            self._record(self._replied, message["id"])
        if "error" in message and method is not None:
            logger.debug(
                "Child target %s rejected %s: %s", path, method, message["error"]
            )
        return path, None, {}


def _settle(cdp, router: "_TargetRouter", message_ids, session_id=None) -> None:
    """Wait until every one of *message_ids* is answered, within a bound.

    Each round trip on *cdp* lets Playwright deliver the replies, which come
    back as events. Stops when *session_id* detaches, and gives up after
    :data:`_SETTLE_SECONDS`: a target that went away never answers, and the
    caller resumes it regardless.
    """
    deadline = time.monotonic() + _SETTLE_SECONDS
    while not all(router.answered(i) for i in message_ids):
        if session_id in router.gone:
            return
        if time.monotonic() >= deadline:
            logger.debug("Child target did not acknowledge its overrides")
            return
        cdp.send("Browser.getVersion")


async def _settle_async(router: "_TargetRouter", message_ids, session_id=None) -> None:
    """:func:`_settle` for async Playwright, whose loop delivers replies."""
    start = time.monotonic()
    deadline = start + _SETTLE_SECONDS
    while not all(router.answered(i) for i in message_ids):
        if session_id in router.gone:
            return
        if time.monotonic() >= deadline:
            logger.debug("Child target did not acknowledge its overrides")
            return
        await asyncio.sleep(0.002)
    logger.debug(
        "Child target acknowledged %s in %.1fms",
        list(message_ids),
        (time.monotonic() - start) * 1000,
    )


def _root_auto_attach(exclude_service_workers: bool) -> tuple[str, dict]:
    if not exclude_service_workers:
        return _AUTO_ATTACH
    method, params = _AUTO_ATTACH
    # Chrome's default filter, minus the service workers held elsewhere.
    return method, dict(
        params,
        filter=[
            {"type": "service_worker", "exclude": True},
            {"type": "browser", "exclude": True},
            {"type": "tab", "exclude": True},
            {},
        ],
    )


def _harden_child_targets(cdp, plan, *, exclude_service_workers=False) -> None:
    """Auto-attach under *cdp* and apply ``plan(target_type, depth)`` to each.

    Every child is resumed even when applying its commands fails: it was
    attached paused, and a paused worker or iframe hangs the page.
    """
    router = _TargetRouter()

    def send(path, method, params) -> int:
        # Read the id before sending: another child's handler can run while
        # this send waits, and would move last_id on.
        outer = router.wrap(path, method, params)
        message_id = router.last_id
        cdp.send(*outer)
        return message_id

    def attached(parent, event) -> None:
        child = parent + (event["sessionId"],)
        logger.debug(
            "Child target %s attached at depth %d (paused=%s)",
            event["targetInfo"]["type"],
            len(child),
            event.get("waitingForDebugger"),
        )
        try:
            sent = [
                send(child, method, params)
                for method, params in plan(event["targetInfo"]["type"], len(child))
            ]
            _settle(cdp, router, sent, session_id=child[-1])
        except Exception:
            logger.debug("Could not harden child target", exc_info=True)
        finally:
            try:
                send(child, "Runtime.runIfWaitingForDebugger", {})
            except Exception:
                logger.debug("Could not resume child target", exc_info=True)

    def received(event) -> None:
        try:
            path, method, params = router.unwrap(event)
            if method == "Target.attachedToTarget":
                attached(path, params)
        except Exception:
            logger.debug("Could not route child target message", exc_info=True)

    cdp.on("Target.attachedToTarget", lambda event: attached((), event))
    cdp.on("Target.receivedMessageFromTarget", received)
    cdp.on(
        "Target.detachedFromTarget",
        lambda event: router._record(router.gone, event.get("sessionId")),
    )
    cdp.send(*_root_auto_attach(exclude_service_workers))


async def _harden_child_targets_async(
    cdp, plan, *, exclude_service_workers=False
) -> None:
    """:func:`_harden_child_targets` for an async Playwright CDP session."""
    router = _TargetRouter()

    async def send(path, method, params) -> int:
        # Read the id before awaiting: other children's handlers run at every
        # await and would move last_id on.
        outer = router.wrap(path, method, params)
        message_id = router.last_id
        await cdp.send(*outer)
        return message_id

    async def attached(parent, event) -> None:
        child = parent + (event["sessionId"],)
        logger.debug(
            "Child target %s attached at depth %d (paused=%s)",
            event["targetInfo"]["type"],
            len(child),
            event.get("waitingForDebugger"),
        )
        try:
            sent = []
            for method, params in plan(event["targetInfo"]["type"], len(child)):
                sent.append(await send(child, method, params))
            await _settle_async(router, sent, session_id=child[-1])
        except Exception:
            logger.debug("Could not harden child target", exc_info=True)
        finally:
            try:
                await send(child, "Runtime.runIfWaitingForDebugger", {})
            except Exception:
                logger.debug("Could not resume child target", exc_info=True)

    async def received(event) -> None:
        try:
            path, method, params = router.unwrap(event)
            if method == "Target.attachedToTarget":
                await attached(path, params)
        except Exception:
            logger.debug("Could not route child target message", exc_info=True)

    async def attached_root(event) -> None:
        await attached((), event)

    cdp.on("Target.attachedToTarget", attached_root)
    cdp.on("Target.receivedMessageFromTarget", received)
    cdp.on(
        "Target.detachedFromTarget",
        lambda event: router._record(router.gone, event.get("sessionId")),
    )
    await cdp.send(*_root_auto_attach(exclude_service_workers))


# Service and shared workers take Chrome's default identity when they start,
# and Patchright resumes (or, for shared workers, detaches from) every worker
# the moment it attaches, so pausing one on start does not hold it for wafer:
# with wafer's handler delayed 400ms, 15 of 15 service workers read the
# launch's empty high-entropy hints. What does hold a service worker is
# Chromium's main-script throttle, which waits for every *flattened* session
# auto-attached under the registering page to resume it
# (devtools_instrumentation.cc, ThrottleServiceWorkerMainScriptFetch; an
# unflattened session never gets one). A flattened child cannot be messaged
# through Playwright's CDPSession, so it only holds the worker while an
# unflattened session from the browser applies the override, and detaching it
# releases the fetch. The override queues until the worker starts and is in
# place before its script runs: 0 of 10 wrong even with the 400ms delay.
#
# Shared workers have no such throttle and attach to no page, so they are
# found through the browser session, and what holds one is its script fetch.
# The browser session intercepts every request of type Other (worker scripts
# are typed Other), and Chrome reports a worker script's networkId as the
# worker's own target id, so each fetch is matched to exactly its worker and
# held until that worker's override is sent; every other request is continued
# at once. Chrome announces the worker before its script fetch starts, so the
# hold is in place when the fetch pauses (measured: every attach arrived
# before its fetch).
#
# A shared worker created again after it closed (same name and URL) keeps its
# target: while wafer's session is attached, Chrome reuses the agent host,
# announces no attach and starts the worker paused for that session
# (shared_worker_devtools_manager.cc, pause_on_start = IsAttached()). Wafer's
# session gets Inspector.targetReloadedAfterCrash instead and resumes it
# there; the override survives the restart. Unresumed, the worker never ran.
_SERVICE_WORKER_HOLD = (
    "Target.setAutoAttach",
    {
        "autoAttach": True,
        "waitForDebuggerOnStart": True,
        "flatten": True,
        "filter": [{"type": "service_worker", "exclude": False}, {"exclude": True}],
    },
)
_SHARED_WORKER_AUTO_ATTACH = (
    "Target.setAutoAttach",
    {
        "autoAttach": True,
        "waitForDebuggerOnStart": True,
        "flatten": True,
        "filter": [{"type": "shared_worker", "exclude": False}, {"exclude": True}],
    },
)
_SHARED_WORKER_FETCH_HOLD = (
    "Fetch.enable",
    {
        "patterns": [
            {"urlPattern": "*", "resourceType": "Other", "requestStage": "Request"}
        ]
    },
)


def _first_attach(handled: dict, target_id: str) -> bool:
    """Record *target_id*; False when it was already handled.

    Bounded, oldest first: a page can start any number of named shared
    workers. A forgotten one that re-attaches is handled once more.
    """
    if target_id in handled:
        return False
    handled[target_id] = None
    while len(handled) > _MAX_HANDLED_SHARED_WORKERS:
        del handled[next(iter(handled))]
    return True


class _BrowserChannel:
    """The one browser-level CDP session wafer keeps per browser.

    It opens the unflattened sessions that carry service and shared workers'
    overrides, and those sessions must stay attached for the worker's life.
    """

    def __init__(self, cdp) -> None:
        self.cdp = cdp
        self.router = _TargetRouter()
        self.handled: dict[str, None] = {}
        self.shared_workers = False
        # Whether the shared-worker listeners are on cdp; a retry after a
        # failed install must not add a second set.
        self.listening = False
        # Shared worker target id -> its paused script fetches, for as long
        # as its override is being sent.
        self.held: dict[str, list[str]] = {}
        # Service worker script URL -> [overrides in flight, paused fetches].
        # A service worker's script fetch carries no networkId, and one
        # registered by a cross-site iframe has no main-script throttle (see
        # _SERVICE_WORKER_HOLD), so its fetch is held by URL instead.
        self.held_urls: dict[str, list] = {}

    def received(self, event) -> tuple[str, dict] | None:
        """Route a worker's reply or event.

        For a worker restarted under one of this channel's sessions, returns
        the command that resumes it.
        """
        try:
            path, method, _ = self.router.unwrap(event)
        except Exception:
            logger.debug("Could not route a worker reply", exc_info=True)
            return None
        if method != "Inspector.targetReloadedAfterCrash" or len(path) != 1:
            return None
        return self.router.wrap(path, "Runtime.runIfWaitingForDebugger", {})

    def paused(self, event) -> tuple[str, dict] | None:
        """Hold a worker's script fetch, or the command continuing it."""
        held = self.held.get(event.get("networkId"))
        if held is None:
            entry = self.held_urls.get((event.get("request") or {}).get("url"))
            held = entry[1] if entry is not None else None
        if held is not None:
            held.append(event["requestId"])
            return None
        return _continue_request(event["requestId"])

    def hold_url(self, url: str) -> None:
        entry = self.held_urls.setdefault(url, [0, []])
        entry[0] += 1

    def release_url(self, url: str) -> list[str]:
        """Drop one hold on *url*; the paused fetches once none is left."""
        entry = self.held_urls.get(url)
        if entry is None:
            return []
        entry[0] -= 1
        if entry[0] > 0:
            return []
        del self.held_urls[url]
        return entry[1]


def _continue_request(request_id: str) -> tuple[str, dict]:
    return "Fetch.continueRequest", {"requestId": request_id}


def _send_quietly(cdp, command, what: str) -> None:
    try:
        cdp.send(*command)
    except Exception:
        logger.debug("Could not %s", what, exc_info=True)


async def _send_quietly_async(cdp, command, what: str) -> None:
    try:
        await cdp.send(*command)
    except Exception:
        logger.debug("Could not %s", what, exc_info=True)


def _browser_channel(browser) -> "_BrowserChannel | None":
    if browser is None:
        logger.debug(
            "No Browser object for this context; service and shared workers "
            "keep Chrome's default identity"
        )
        return None
    channel = getattr(browser, "_wafer_channel", None)
    if isinstance(channel, _BrowserChannel):
        return channel
    try:
        cdp = browser.new_browser_cdp_session()
    except Exception:
        logger.warning(
            "Could not open a browser CDP session; service and shared workers "
            "keep Chrome's default identity",
            exc_info=True,
        )
        return None
    channel = _BrowserChannel(cdp)

    def received(event) -> None:
        resume = channel.received(event)
        if resume is not None:
            _send_quietly(cdp, resume, "resume a restarted worker")

    cdp.on("Target.receivedMessageFromTarget", received)
    browser._wafer_channel = channel
    return channel


async def _browser_channel_async(browser) -> "_BrowserChannel | None":
    """:func:`_browser_channel` for async Playwright; one session per browser."""
    if browser is None:
        logger.debug(
            "No Browser object for this context; service and shared workers "
            "keep Chrome's default identity"
        )
        return None
    channel = getattr(browser, "_wafer_channel", None)
    if isinstance(channel, _BrowserChannel):
        return channel
    if isinstance(channel, asyncio.Future):
        return await channel
    opening = asyncio.get_running_loop().create_future()
    browser._wafer_channel = opening
    channel = None
    try:
        cdp = await browser.new_browser_cdp_session()
        channel = _BrowserChannel(cdp)

        async def received(event, channel=channel) -> None:
            resume = channel.received(event)
            if resume is not None:
                await _send_quietly_async(
                    channel.cdp, resume, "resume a restarted worker"
                )

        cdp.on("Target.receivedMessageFromTarget", received)
    except Exception:
        logger.warning(
            "Could not open a browser CDP session; service and shared workers "
            "keep Chrome's default identity",
            exc_info=True,
        )
    finally:
        # Also on cancellation: an unresolved future left cached here would
        # make every later page on this browser wait on it forever.
        browser._wafer_channel = channel
        if not opening.done():
            opening.set_result(channel)
    return channel


def _worker_override_messages(channel, session_id: str, ua_params: dict):
    return [
        channel.router.wrap((session_id,), method, params)
        for method, params in _child_target_commands(
            "worker", headless=True, ua_params=ua_params, scripts=()
        )
    ]


def _override_worker(channel, target_id: str, ua_params: dict) -> str:
    """Attach unflattened from the browser and send the worker override.

    Returns the session, which must stay attached: it carries the override.
    """
    session_id = channel.cdp.send(
        "Target.attachToTarget", {"targetId": target_id, "flatten": False}
    )["sessionId"]
    for message in _worker_override_messages(channel, session_id, ua_params):
        channel.cdp.send(*message)
    return session_id


async def _override_worker_async(channel, target_id: str, ua_params: dict) -> str:
    session_id = (
        await channel.cdp.send(
            "Target.attachToTarget", {"targetId": target_id, "flatten": False}
        )
    )["sessionId"]
    for message in _worker_override_messages(channel, session_id, ua_params):
        await channel.cdp.send(*message)
    return session_id


def _resume_after_override(channel, session_id: str) -> tuple[str, dict]:
    """The command that starts a paused worker after its override.

    Sent on the session that carried the override, so the worker processes
    the override first. With the driver started under hardened_driver_env,
    nothing else resumes a shared worker; without it, Playwright already has.
    """
    return channel.router.wrap((session_id,), "Runtime.runIfWaitingForDebugger", {})


def _harden_shared_workers(browser, ua_params: dict) -> None:
    """Give every shared worker *browser* starts the page's UA override.

    Installed once per browser, with the first page's override: every shared
    worker in the browser gets it.
    """
    channel = _browser_channel(browser)
    if channel is None or channel.shared_workers:
        return
    channel.shared_workers = True
    cdp = channel.cdp

    def attached(event) -> None:
        info = event["targetInfo"]
        # The unflattened sessions this channel opens emit attach events too,
        # for service workers and for the shared worker itself. Never detach
        # those: that drops the override they carry (measured).
        if info["type"] != "shared_worker" or not _first_attach(
            channel.handled, info["targetId"]
        ):
            return
        target_id = info["targetId"]
        channel.held[target_id] = []
        try:
            session_id = _override_worker(channel, target_id, ua_params)
            _send_quietly(
                cdp,
                _resume_after_override(channel, session_id),
                "resume shared worker",
            )
        except Exception:
            # Let a later attach of the same worker try again.
            channel.handled.pop(target_id, None)
            logger.debug("Could not harden shared worker", exc_info=True)
        finally:
            for request_id in channel.held.pop(target_id, ()):
                _send_quietly(
                    cdp, _continue_request(request_id), "release a worker script"
                )
            _send_quietly(
                cdp,
                ("Target.detachFromTarget", {"sessionId": event["sessionId"]}),
                "release shared worker",
            )

    def paused(event) -> None:
        command = channel.paused(event)
        if command is not None:
            _send_quietly(cdp, command, "continue a request")

    if not channel.listening:
        # Before Fetch.enable: a paused request nothing continues never loads.
        cdp.on("Target.attachedToTarget", attached)
        cdp.on("Fetch.requestPaused", paused)
        channel.listening = True
    try:
        cdp.send(*_SHARED_WORKER_FETCH_HOLD)
    except Exception:
        logger.debug("Could not hold shared worker scripts", exc_info=True)
    try:
        cdp.send(*_SHARED_WORKER_AUTO_ATTACH)
    except Exception:
        channel.shared_workers = False
        logger.warning(
            "Could not auto-attach shared workers; they keep Chrome's default "
            "identity",
            exc_info=True,
        )


async def _harden_shared_workers_async(browser, ua_params: dict) -> None:
    """:func:`_harden_shared_workers` for an async Playwright browser."""
    channel = await _browser_channel_async(browser)
    if channel is None or channel.shared_workers:
        return
    channel.shared_workers = True
    cdp = channel.cdp

    # Both handlers are coroutines, so their tasks start in event order: the
    # hold is recorded before a script fetch that follows the attach pauses.
    async def attached(event) -> None:
        info = event["targetInfo"]
        if info["type"] != "shared_worker" or not _first_attach(
            channel.handled, info["targetId"]
        ):
            return
        target_id = info["targetId"]
        channel.held[target_id] = []
        try:
            session_id = await _override_worker_async(channel, target_id, ua_params)
            await _send_quietly_async(
                cdp,
                _resume_after_override(channel, session_id),
                "resume shared worker",
            )
        except Exception:
            # Let a later attach of the same worker try again.
            channel.handled.pop(target_id, None)
            logger.debug("Could not harden shared worker", exc_info=True)
        finally:
            for request_id in channel.held.pop(target_id, ()):
                await _send_quietly_async(
                    cdp, _continue_request(request_id), "release a worker script"
                )
            await _send_quietly_async(
                cdp,
                ("Target.detachFromTarget", {"sessionId": event["sessionId"]}),
                "release shared worker",
            )

    async def paused(event) -> None:
        command = channel.paused(event)
        if command is not None:
            await _send_quietly_async(cdp, command, "continue a request")

    if not channel.listening:
        # Before Fetch.enable: a paused request nothing continues never loads.
        cdp.on("Target.attachedToTarget", attached)
        cdp.on("Fetch.requestPaused", paused)
        channel.listening = True
    try:
        await cdp.send(*_SHARED_WORKER_FETCH_HOLD)
    except Exception:
        logger.debug("Could not hold shared worker scripts", exc_info=True)
    try:
        await cdp.send(*_SHARED_WORKER_AUTO_ATTACH)
    except Exception:
        channel.shared_workers = False
        logger.warning(
            "Could not auto-attach shared workers; they keep Chrome's default "
            "identity",
            exc_info=True,
        )


def _hold_service_workers(page, browser, ua_params: dict) -> bool:
    """Hold each service worker *page* registers until its override is sent.

    True when installed, so the page's own auto-attach can leave service
    workers to it.
    """
    channel = _browser_channel(browser)
    if channel is None:
        return False
    try:
        holder = page.context.new_cdp_session(page)
    except Exception:
        logger.warning("Could not hold service workers", exc_info=True)
        return False

    def attached(event) -> None:
        info = event["targetInfo"]
        url = info.get("url") or ""
        is_new = info["type"] == "service_worker" and _first_attach(
            channel.handled, info["targetId"]
        )
        if is_new and url:
            channel.hold_url(url)
        try:
            if is_new:
                _override_worker(channel, info["targetId"], ua_params)
        except Exception:
            channel.handled.pop(info["targetId"], None)
            logger.debug("Could not harden service worker", exc_info=True)
        finally:
            if is_new and url:
                for request_id in channel.release_url(url):
                    _send_quietly(
                        channel.cdp,
                        _continue_request(request_id),
                        "release a worker script",
                    )
            # Detaching drops this session's hold on the script fetch.
            try:
                holder.send(
                    "Target.detachFromTarget", {"sessionId": event["sessionId"]}
                )
            except Exception:
                logger.debug("Could not release service worker", exc_info=True)

    holder.on("Target.attachedToTarget", attached)
    try:
        holder.send(*_SERVICE_WORKER_HOLD)
    except Exception:
        logger.warning("Could not hold service workers", exc_info=True)
        try:
            holder.detach()
        except Exception:
            pass
        return False
    return True


async def _hold_service_workers_async(page, browser, ua_params: dict) -> bool:
    """:func:`_hold_service_workers` for an async Playwright page."""
    channel = await _browser_channel_async(browser)
    if channel is None:
        return False
    try:
        holder = await page.context.new_cdp_session(page)
    except Exception:
        logger.warning("Could not hold service workers", exc_info=True)
        return False

    async def attached(event) -> None:
        info = event["targetInfo"]
        url = info.get("url") or ""
        is_new = info["type"] == "service_worker" and _first_attach(
            channel.handled, info["targetId"]
        )
        if is_new and url:
            channel.hold_url(url)
        try:
            if is_new:
                await _override_worker_async(channel, info["targetId"], ua_params)
        except Exception:
            channel.handled.pop(info["targetId"], None)
            logger.debug("Could not harden service worker", exc_info=True)
        finally:
            if is_new and url:
                for request_id in channel.release_url(url):
                    await _send_quietly_async(
                        channel.cdp,
                        _continue_request(request_id),
                        "release a worker script",
                    )
            try:
                await holder.send(
                    "Target.detachFromTarget", {"sessionId": event["sessionId"]}
                )
            except Exception:
                logger.debug("Could not release service worker", exc_info=True)

    holder.on("Target.attachedToTarget", attached)
    try:
        await holder.send(*_SERVICE_WORKER_HOLD)
    except Exception:
        logger.warning("Could not hold service workers", exc_info=True)
        try:
            await holder.detach()
        except Exception:
            pass
        return False
    return True


def _page_scripts(headless: bool, viewport: tuple[int, int] | None) -> list[str]:
    """The init scripts for a page and its iframes.

    One geometry for the whole page: the iframes must report the window the
    top document does. *viewport* ``None`` falls back to deriving it in the
    top document alone, which leaves iframes unpatched.
    """
    if not headless:
        return []
    if viewport is None:
        return [_HEADLESS_FIX_SCRIPT]
    return [_headless_fix_script(_headless_geometry(*viewport))]


def _viewport_of(size) -> tuple[int, int] | None:
    if isinstance(size, (list, tuple)) and len(size) == 2:
        width, height = size
    elif isinstance(size, dict):
        width, height = size.get("width"), size.get("height")
    else:
        return None
    if isinstance(width, int) and isinstance(height, int) and width > 0 and height > 0:
        return width, height
    return None


def _browser_identity(
    version: dict, user_agent: str | None, *, headless: bool
) -> tuple[str, str | None]:
    """The user agent and full version to harden a page with.

    *version* is CDP ``Browser.getVersion``, read from the launched browser so
    the full version is the binary's own (a reduced UA says only ``MAJOR.0.0.0``)
    and nothing falls back to wafer's emulation tables.
    """
    product = version.get("product") or ""
    raw_ua = version.get("userAgent") or ""
    if product.startswith("HeadlessChrome/"):
        logger.warning(
            "harden_page: this browser is chrome-headless-shell (%s), the old "
            "headless build Playwright runs for headless=True when no channel or "
            "executable_path is given. It ignores --headless=new and brands its "
            "workers HeadlessChrome; launch a full Chrome with channel='chrome' "
            "(or executable_path) instead.",
            product,
        )
    elif headless and "HeadlessChrome" in raw_ua:
        logger.warning(
            "harden_page: the browser's own user agent still says "
            "HeadlessChrome, so it was launched without "
            "hardened_launch_config(user_agent=...). Pages and iframes are "
            "corrected, but service workers and shared workers report "
            "HeadlessChrome."
        )
    full_version = product.partition("/")[2] or None
    ua = user_agent or scrub_headless_ua(raw_ua)
    if not ua:
        # Without a UA there is no override, and the page keeps whatever brand
        # the binary reports -the exact leak this exists to close.
        raise RuntimeError(f"Browser did not report a user agent (got {version!r})")
    return ua, full_version


def _install_init_script_fallback(page, scripts, cdp) -> None:
    """Re-apply fingerprint scripts on navigation when CDP injection is inert.

    ``Page.addScriptToEvaluateOnNewDocument`` has returned an identifier and
    then never executed under some Patchright builds, silently turning every
    script registered alongside it into a no-op. So each navigation re-applies
    them through *cdp*'s ``Runtime.evaluate``, which runs in the document's
    own world, where page scripts read the values.

    Not ``Frame.evaluate``: Patchright runs that in an isolated world page
    scripts cannot see, and Playwright evaluates with ``userGesture: true``,
    which leaves ``navigator.userActivation.hasBeenActive`` true on a page
    nobody touched.

    This lands just after document-start rather than before it, so it is a
    fallback for an injection that is otherwise doing nothing at all, not a
    replacement for real init-time injection. When the CDP registration did
    run, each script finds its own patch already applied. The scripts are also
    applied once, at once, to whatever document the page already shows.
    """

    if not scripts:
        return

    def _apply() -> None:
        # Applied independently: these patch unrelated surfaces, so one
        # failing must not deprive the page of the others.
        for source in scripts:
            try:
                cdp.send(
                    "Runtime.evaluate", {"expression": source, "userGesture": False}
                )
            except Exception:
                logger.debug("Init-script fallback failed", exc_info=True)

    def _reapply(frame) -> None:
        try:
            if frame is not page.main_frame:
                return
        except Exception:
            return
        _apply()

    page.on("framenavigated", _reapply)
    # And the document already there: a popup is hardened only after its first
    # document loaded, so without this that document never got the patches.
    # On a page still at about:blank it patches nothing that will be kept.
    _apply()


async def _install_init_script_fallback_async(page, scripts, cdp) -> None:
    """:func:`_install_init_script_fallback` for an async Playwright page."""

    if not scripts:
        return

    async def _apply() -> None:
        for source in scripts:
            try:
                await cdp.send(
                    "Runtime.evaluate", {"expression": source, "userGesture": False}
                )
            except Exception:
                logger.debug("Init-script fallback failed", exc_info=True)

    async def _reapply(frame) -> None:
        try:
            if frame is not page.main_frame:
                return
        except Exception:
            return
        await _apply()

    page.on("framenavigated", _reapply)
    await _apply()


# Read through CDP rather than Page.evaluate, which would mark the page as
# user-activated (see _install_init_script_fallback).
_WINDOW_STATE = (
    "JSON.stringify([innerWidth, innerHeight, devicePixelRatio, outerWidth,"
    " outerHeight, screen.width, screen.availTop, screen.colorDepth])"
)


def _native_window(state) -> bool:
    """Whether *state* is the launch's real display rather than an emulation.

    hardened_launch_config describes the Mac's display, menu bar included, and
    a context without viewport emulation reports it as headed Chrome does: a
    work area below the menu bar, an outer window the toolbar's height taller
    than the page, a screen wider than the page. Viewport emulation reports
    the viewport as the screen, with no menu bar.
    """
    try:
        inner_w, inner_h, _, _, outer_h, screen_w, avail_top, _ = json.loads(state)
        return avail_top > 0 and outer_h > inner_h and screen_w > inner_w
    except (TypeError, ValueError):
        return False


def _check_window_state(
    state, *, headless: bool, platform: str | None = None
) -> tuple[int, int] | None:
    """The viewport from *state*, warning about a scale factor no Mac has."""
    host = sys.platform if platform is None else platform
    try:
        width, height, ratio = json.loads(state)[:3]
    except (TypeError, ValueError):
        return None
    if headless and host == "darwin" and ratio != 2:
        logger.warning(
            "harden_page: devicePixelRatio is %s; pass device_scale_factor=2 to "
            "new_context. hardened_launch_config forces 2 for every frame of a "
            "headless macOS browser, so any other value leaves the top document "
            "disagreeing with its iframes.",
            ratio,
        )
    return _viewport_of((width, height))


# Pages hardened here, mapped to the CDP session that hardened them, so the
# solver can read page state without Page.evaluate (see _quiet_read).
_PAGE_SESSIONS: "weakref.WeakKeyDictionary" = weakref.WeakKeyDictionary()
_DOCUMENT_LENGTH = (
    "document.documentElement ? document.documentElement.outerHTML.length : 0"
)


def _quiet_read(page, expression: str):
    """Evaluate *expression* in *page*'s own world, without a user gesture.

    Playwright sends every evaluation with ``userGesture: true``, which marks
    the frame and its ancestors user-activated: a solver reading page state
    left ``navigator.userActivation.hasBeenActive`` true on a page nobody had
    touched. Patchright also evaluates in an isolated world, which reads the
    window without the page's fingerprint patches. *expression* is a plain
    expression, not a function. A page this module did not harden falls back
    to ``page.evaluate``.
    """
    try:
        cdp = _PAGE_SESSIONS.get(page)
    except TypeError:
        cdp = None
    if cdp is None:
        return page.evaluate(expression)
    reply = cdp.send(
        "Runtime.evaluate",
        {
            "expression": expression,
            "returnByValue": True,
            "awaitPromise": True,
            "userGesture": False,
        },
    )
    if reply.get("exceptionDetails"):
        raise RuntimeError(
            f"Page read failed: {reply['exceptionDetails'].get('text')}"
        )
    return (reply.get("result") or {}).get("value")


def _harden_popups(page, harden) -> None:
    """Run *harden* on every popup *page* opens.

    Patchright resumes a new tab itself, before this can reach it. Its first
    document still starts right when the driver runs under
    hardened_driver_env: the preload sends the override harden_page
    published right before that resume, and on macOS headless the launch's
    native display needs no script. Hardening the popup as it appears adds
    the rest (iframes, workers) for it and every later navigation.
    """

    def on_popup(popup) -> None:
        try:
            harden(popup)
        except Exception:
            logger.debug("Could not harden popup", exc_info=True)

    page.on("popup", on_popup)


def _harden_popups_async(page, harden) -> None:
    """:func:`_harden_popups` for an async Playwright page."""

    async def on_popup(popup) -> None:
        try:
            await harden(popup)
        except Exception:
            logger.debug("Could not harden popup", exc_info=True)

    page.on("popup", on_popup)


def _apply_page_hardening(
    page, cdp, *, headless, ua_params, scripts, browser=None
) -> None:
    """Harden *page* and everything it starts, given its scripts and UA.

    The part :func:`harden_page` and the solver share once each has settled
    which scripts and which user agent the page gets. In headless mode,
    *browser* (``None`` when the context has no Browser object) also carries
    the service- and shared-worker overrides.
    """
    for method, params in _page_hardening_commands(
        headless=headless, ua_params=ua_params, scripts=scripts
    ):
        cdp.send(method, params)
    held = False
    if headless and ua_params:
        held = _hold_service_workers(page, browser, ua_params)
        _harden_shared_workers(browser, ua_params)
    _harden_child_targets(
        cdp,
        lambda target_type, depth: _child_target_commands(
            target_type,
            headless=headless,
            ua_params=ua_params,
            scripts=scripts,
            depth=depth,
        ),
        exclude_service_workers=held,
    )
    _install_init_script_fallback(page, scripts, cdp)
    try:
        _PAGE_SESSIONS[page] = cdp
    except TypeError:
        pass


async def _apply_page_hardening_async(
    page, cdp, *, headless, ua_params, scripts, browser=None
) -> None:
    """:func:`_apply_page_hardening` for an async Playwright page."""
    for method, params in _page_hardening_commands(
        headless=headless, ua_params=ua_params, scripts=scripts
    ):
        await cdp.send(method, params)
    held = False
    if headless and ua_params:
        held = await _hold_service_workers_async(page, browser, ua_params)
        await _harden_shared_workers_async(browser, ua_params)
    await _harden_child_targets_async(
        cdp,
        lambda target_type, depth: _child_target_commands(
            target_type,
            headless=headless,
            ua_params=ua_params,
            scripts=scripts,
            depth=depth,
        ),
        exclude_service_workers=held,
    )
    await _install_init_script_fallback_async(page, scripts, cdp)


def harden_page(page, *, headless: bool, user_agent: str | None = None) -> None:
    """Apply the per-page half of wafer's browser hardening.

    :func:`hardened_launch_config` covers what is fixed at launch. This covers
    what Chrome only accepts per target, through CDP, for the page and for
    every iframe and worker it starts:

    - the user agent with full client-hint metadata, so ``sec-ch-ua``,
      ``sec-ch-ua-full-version-list`` and ``navigator.userAgentData`` agree
      with it in every frame and worker;
    - ``navigator.languages``;
    - in headless mode on macOS, the window and screen patch with one
      geometry for the page and all its iframes, and ``color-gamut``.

    This is the same per-page setup :class:`BrowserSolver` applies.

    Call it on a new page before its first navigation, with the same
    ``headless`` the browser was launched with, and do not pass
    ``user_agent=`` to ``new_context``: Playwright attaches its own client-hint
    metadata to a context-level user agent, and cross-site iframes then report
    ``architecture: x86`` and ``platformVersion: 10.15.7`` regardless of the
    host. ``user_agent`` here defaults to the browser's own, scrubbed of
    ``HeadlessChrome``; pass it only to send a different Chrome user agent.

    Calling it again on the same page does nothing. The CDP session it opens
    stays attached for the page's lifetime; detaching it would unregister the
    scripts and release the iframes and workers it holds. Pages created
    separately (``new_page``) need their own call. The window geometry is taken
    from the viewport at this call.

    A popup this page opens is hardened as soon as it appears. With the
    driver started under :func:`hardened_driver_env`, its first document
    already starts with this page's user-agent override (the preload sends it
    before Patchright resumes the new tab); without it, that document's
    earliest scripts read the launch's empty high-entropy client hints.

    New iframes and workers are held paused until their overrides are in, and
    with the sync API only your thread's Playwright calls deliver the events
    that release them: wait with ``page.wait_for_timeout``, never
    ``time.sleep``, while the page is live.

    In headless mode it also holds each service worker the page or any of its
    iframes registers until its override is in place (Chromium's main-script
    throttle through a second page session, and a script-fetch hold for one
    a cross-site iframe registers), and opens one browser-level CDP session
    per browser for the service- and shared-worker overrides. Shared workers
    are held only when the driver runs under :func:`hardened_driver_env`;
    otherwise one that reads its high-entropy client hints within its first
    milliseconds can still see them empty.

    Requires a full Chrome, and in headless mode the launch must carry
    ``hardened_launch_config(user_agent=...)``: service and shared workers read
    their ``navigator.userAgent`` from the browser default before any session
    can change it. Without it both report ``HeadlessChrome``, and this logs a
    warning.
    """
    if getattr(page, "_wafer_hardened", False) is True:
        return
    cdp = page.context.new_cdp_session(page)
    version = cdp.send("Browser.getVersion")
    ua, full_version = _browser_identity(version, user_agent, headless=headless)
    state = cdp.send(
        "Runtime.evaluate", {"expression": _WINDOW_STATE, "returnByValue": True}
    )
    value = state.get("result", {}).get("value")
    measured = _check_window_state(value, headless=headless)
    viewport = _viewport_of(page.viewport_size) or measured
    # The launch's real display needs no window script (_native_window).
    scripts = (
        [] if headless and _native_window(value) else _page_scripts(headless, viewport)
    )
    ua_params = _ua_override_params(ua, full_version)
    # The pages the driver sets up itself, popups included, start with it too.
    _publish_ua_override((version or {}).get("userAgent"), ua_params)
    _apply_page_hardening(
        page,
        cdp,
        headless=headless,
        ua_params=ua_params,
        scripts=scripts,
        browser=page.context.browser,
    )
    _harden_popups(
        page, lambda popup: harden_page(popup, headless=headless, user_agent=user_agent)
    )
    page._wafer_hardened = True


async def harden_page_async(
    page, *, headless: bool, user_agent: str | None = None
) -> None:
    """:func:`harden_page` for an async Playwright page."""
    if getattr(page, "_wafer_hardened", False) is True:
        return
    cdp = await page.context.new_cdp_session(page)
    version = await cdp.send("Browser.getVersion")
    ua, full_version = _browser_identity(version, user_agent, headless=headless)
    state = await cdp.send(
        "Runtime.evaluate", {"expression": _WINDOW_STATE, "returnByValue": True}
    )
    value = state.get("result", {}).get("value")
    measured = _check_window_state(value, headless=headless)
    viewport = _viewport_of(page.viewport_size) or measured
    # The launch's real display needs no window script (_native_window).
    scripts = (
        [] if headless and _native_window(value) else _page_scripts(headless, viewport)
    )
    ua_params = _ua_override_params(ua, full_version)
    _publish_ua_override((version or {}).get("userAgent"), ua_params)
    await _apply_page_hardening_async(
        page,
        cdp,
        headless=headless,
        ua_params=ua_params,
        scripts=scripts,
        browser=page.context.browser,
    )
    _harden_popups_async(
        page,
        lambda popup: harden_page_async(
            popup, headless=headless, user_agent=user_agent
        ),
    )
    page._wafer_hardened = True


@dataclass
class _BrowseState:
    """Tracks playback position within a browse recording."""

    rows: list[dict[str, float]]
    index: int
    time_scale: float
    origin_x: float
    origin_y: float
    scroll_scale: float
    current_x: float
    current_y: float


@dataclass
class CapturedResponse:
    """An HTTP response captured during interception or passthrough.

    ``headers`` is the flat (last-wins / joined) header dict; ``set_cookie``
    preserves the individual ``Set-Cookie`` values, which the flat dict would
    collapse (a response can carry several Set-Cookie headers and they must
    stay separate to round-trip into the wreq jar).
    """

    url: str
    status: int
    headers: dict[str, str]
    body: bytes
    set_cookie: list[str] = field(default_factory=list)


@dataclass
class SolveResult:
    """Result of browser-based challenge solving."""

    cookies: list[dict]
    user_agent: str
    extras: dict | None = None
    response: CapturedResponse | None = None
    # Real full Chrome version of the solving browser (e.g. "150.0.7871.125"),
    # from browser.version. The UA is version-reduced ("Chrome/150.0.0.0"), so
    # this carries the true build the session needs to reproduce the browser's
    # sec-ch-ua-full-version-list when replaying UA/CH-bound WAF cookies.
    browser_version: str | None = None
    # True when the browser's validated main document is returned without a
    # transferable clearance identity (Cloudflare was absent, or TMD reached
    # real browser content without minting x5sec). The session must merge
    # cookies without pinning or rebuilding.
    challenge_absent: bool = False


@dataclass
class InterceptResult:
    """Result of iframe interception.

    Contains all cookies and HTTP responses captured from the target
    domain while the embedder page (and its iframes) loaded.
    """

    cookies: list[dict]
    responses: list[CapturedResponse]
    user_agent: str


def _current_document(document_responses: list, navigation_response):
    """The response the page's current document came from.

    The last main-frame document response recorded, else the goto() response
    when none was recorded (a cached or synthetic document).
    """
    return document_responses[-1] if document_responses else navigation_response


def _response_status(response) -> int:
    if response is None:
        return 200
    try:
        return int(response.status)
    except (TypeError, ValueError):
        return 200



def _render_budget(
    start: float, timeout: float, challenge_budget: float | None
) -> dict:
    """The deadline a render shares with its worker, and how far it may move."""
    deadline = start + timeout
    challenge_deadline = None
    if challenge_budget is not None and challenge_budget > timeout:
        challenge_deadline = start + challenge_budget
    return {"deadline": deadline, "challenge_deadline": challenge_deadline}


def _extend_render_budget(
    budget: dict | None, challenge_value: str, deadline: float
) -> float:
    """Move a render's deadline for a slow in-place challenge, if allowed."""
    if (
        budget is None
        or challenge_value not in _SLOW_INPLACE_CHALLENGES
        or budget.get("challenge_deadline") is None
        or budget["challenge_deadline"] <= deadline
    ):
        return deadline
    extended = budget["challenge_deadline"]
    budget["deadline"] = extended
    logger.info(
        "Render landed on a %s challenge; its budget runs %.0fs more",
        challenge_value,
        extended - time.monotonic(),
    )
    return extended

class BrowserSolver:
    """Solves WAF challenges using a real Chrome browser via patchright.

    Manages a persistent Chrome instance with idle timeout. Cookies are
    extracted after challenge resolution and returned for injection into
    the wreq session.

    Headless mode is supported but has lower solve coverage. Browser-bound
    clearance replay aligns the session's UA/client hints to the launched
    Chrome version when it differs from the newest wreq emulation.
    """

    def __init__(
        self,
        headless: bool = False,
        idle_timeout: float = 300.0,
        solve_timeout: float = 30.0,
        proxy: str | None = None,
        egress_guard_proxy: str | None = None,
        executable_path: str | os.PathLike[str] | None = None,
    ):
        try:
            import patchright  # noqa: F401
        except ImportError:
            raise ImportError(
                "BrowserSolver requires the [browser] extra. "
                "Install it with: pip install wafer-py[browser]"
            ) from None
        self._headless = headless
        # One window size for this solver's headless macOS browser, as a real
        # user keeps one; chosen on the first launch (see _solver_viewport).
        self._viewport: tuple[int, int] | None = None
        self._idle_timeout = idle_timeout
        self._solve_timeout = solve_timeout
        self._playwright = None
        self._browser = None
        # Reentrant because a custom worker callback may close the solver
        # while it already owns the browser-operation lock.
        self._lock = threading.RLock()
        self._last_used: float = 0.0
        self._browser_ua: str | None = None
        self._browser_version: str | None = None
        self._runtime_ready = threading.Event()
        # Determined with real Patchright input before the first site page.
        # ``None`` means no browser has been probed yet; after probing it is
        # immutable for this solver's configured executable.
        self._needs_screenxy_patch: bool | None = None
        # A transport session can read this while the browser worker is busy.
        # Publish one immutable pair at a time; never take the long-lived
        # browser-operation lock in that read path.
        self._identity_snapshot: tuple[str, str] | None = None
        self._identity_lock = threading.Lock()
        if proxy is not None and not _valid_proxy_url(proxy):
            raise ValueError("proxy must be a valid HTTP(S) or SOCKS5 proxy URL")
        if egress_guard_proxy is not None and not _valid_egress_guard_url(
            egress_guard_proxy
        ):
            raise ValueError(
                "egress_guard_proxy must be an unauthenticated loopback SOCKS5 URL"
            )
        if proxy is not None and egress_guard_proxy is not None:
            raise ValueError("proxy and egress_guard_proxy cannot be combined")
        self._proxy_server = proxy
        self._egress_guard_proxy = egress_guard_proxy
        if executable_path is not None:
            executable_path = os.fspath(executable_path)
            if not executable_path:
                raise ValueError("executable_path must not be empty")
        self._executable_path = executable_path
        # Patchright's synchronous Playwright objects are greenlet-bound to
        # the thread that created them. Every public browser operation,
        # including preflight and close, must therefore use one dedicated
        # worker for this solver's entire lifetime.
        self._executor = _DaemonSerialExecutor("wafer-browser")
        self._executor_lock = threading.Lock()
        self._executor_closed = False
        self._close_future = None
        self._worker_ident: int | None = None
        # Recording caches (lazy-loaded on first PX encounter)
        self._idle_recordings: list[dict] | None = None
        self._path_recordings: list[dict] | None = None
        self._hold_recordings: list[dict] | None = None
        self._drag_recordings: list[dict] | None = None
        self._slide_recordings: list[dict] | None = None
        self._browse_recordings: list[dict] | None = None
        self._grid_recordings: list[dict] | None = None
        # TMD rejects a trajectory, not merely a browser context. Preserve a
        # bounded cross-context history so transport-level fresh-context
        # retries never replay the exact recording that just failed.
        self._baxia_recent_drag_recordings: list[str] = []

    @property
    def proxy_server(self) -> str | None:
        """Upstream proxy shared with the wafer HTTP session."""

        return self._proxy_server

    @property
    def egress_guard_proxy(self) -> str | None:
        """Browser-only local egress guard, not an upstream identity proxy."""

        return self._egress_guard_proxy

    @property
    def browser_identity(self) -> tuple[str, str] | None:
        """The already-preflighted browser UA and full Chrome version.

        This accessor deliberately performs no browser I/O.  A session can
        therefore consume it while it is being constructed, before its first
        protected HTTP request, without changing BrowserSolver lifecycle or
        issuing an unexpected navigation.  ``None`` means this solver has not
        completed a usable preflight (or has since been closed).
        """

        # This deliberately does not touch ``_lock``: a challenge may own it
        # for its full solve timeout, while a first HTTP request still needs
        # the already-established identity. Tuple replacement is atomic, and
        # the tiny lock makes that publication contract explicit without
        # waiting on any browser I/O.
        with self._identity_lock:
            return self._identity_snapshot

    @property
    def runtime_ready(self) -> bool:
        """Whether the preflighted Chrome process is currently connected."""

        return self._runtime_ready.is_set()

    def _publish_browser_identity(self) -> None:
        """Atomically publish the browser identity once both fields exist."""

        if not self._browser_ua or not self._browser_version:
            return
        snapshot = (self._browser_ua, self._browser_version)
        with self._identity_lock:
            self._identity_snapshot = snapshot

    def _clear_browser_identity(self) -> None:
        with self._identity_lock:
            self._identity_snapshot = None

    def configure_proxy(self, proxy: str) -> None:
        """Configure browser-wide proxying before Chromium is launched."""

        if not _valid_proxy_url(proxy):
            raise ValueError("proxy must be a valid HTTP(S) or SOCKS5 proxy URL")
        with self._lock:
            if self._browser is not None:
                raise RuntimeError(
                    "browser proxy must be configured before browser launch"
                )
            if self._egress_guard_proxy is not None:
                raise RuntimeError(
                    "an upstream proxy cannot be combined with the browser egress guard"
                )
            self._proxy_server = proxy

    def configure_egress_guard(self, proxy: str) -> None:
        """Configure a browser-only local SOCKS5 guard before launch."""

        if not _valid_egress_guard_url(proxy):
            raise ValueError(
                "egress guard must be an unauthenticated loopback SOCKS5 URL"
            )
        with self._lock:
            if self._browser is not None:
                raise RuntimeError(
                    "browser egress guard must be configured before launch"
                )
            if self._proxy_server is not None:
                raise RuntimeError(
                    "browser egress guard cannot be combined with an upstream proxy"
                )
            self._egress_guard_proxy = proxy

    def proxy_matches(self, proxy: str | None) -> bool:
        """Whether *proxy* names the browser's exact configured egress."""

        if proxy is None or self._proxy_server is None:
            return proxy is None and self._proxy_server is None
        if not _valid_proxy_url(proxy):
            return False
        return _proxy_identity(proxy) == _proxy_identity(self._proxy_server)

    _browser_installed: set[tuple[str, str]] = set()
    _browser_install_lock = threading.Lock()

    def _expected_browser_version(self) -> str:
        """Return the exact Chrome version used by wafer's transport hints."""

        # Keep browser identity tied to the public default rather than a
        # nearby installed Chrome.  A local import avoids a cycle while this
        # module is first imported.
        from wafer._base import DEFAULT_EMULATION

        expected = chrome_full_version(DEFAULT_EMULATION)
        if expected is None:
            raise RuntimeError("wafer default emulation is not Chrome")
        return expected

    def _browser_executable(self) -> str:
        """Resolve the caller-pinned or branded Chrome executable."""

        if self._executable_path is not None:
            return self._executable_path
        chrome = _system_chrome_executable()
        if chrome is None:
            raise RuntimeError(
                "No executable branded Google Chrome was found. Configure "
                "BrowserSolver(executable_path=...) with the exact Chrome "
                "version selected by wafer's emulation."
            )
        return chrome

    def _ensure_browser_installed(self, deadline: float | None = None) -> None:
        """Validate the exact Chrome version before Patchright launches it."""

        chrome = self._browser_executable()
        expected = self._expected_browser_version()
        cache_key = (os.path.realpath(chrome), expected)
        if cache_key in BrowserSolver._browser_installed:
            return
        if deadline is None:
            BrowserSolver._browser_install_lock.acquire()
        else:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not BrowserSolver._browser_install_lock.acquire(
                timeout=remaining
            ):
                raise TimeoutError("Browser install check exceeded solve timeout")
        try:
            # Another solver may have completed installation while this one
            # waited for the process-wide installer lock.
            if cache_key in BrowserSolver._browser_installed:
                return
            timeout = None
            if deadline is not None:
                timeout = deadline - time.monotonic()
                if timeout <= 0:
                    raise TimeoutError("Browser version check exceeded solve timeout")
            # _browser_executable_version already rejects an unreadable or
            # non-Chrome binary, so `actual` is a real Chrome version here.
            #
            # Do NOT require it to equal the emulation's build. Chrome
            # auto-updates and wreq's newest Emulation lags it, so an equality
            # gate makes every solver path dead on an ordinary machine the
            # week Chrome ships an update. Agreement between the browser and
            # wafer's transport hints is still required for browser-bound
            # clearance replay. Those solve paths achieve it the other way
            # round, by FingerprintManager.pin_to_browser() moving wafer onto
            # the installed browser's exact UA/client hints.
            actual = _browser_executable_version(chrome, timeout)
            if actual != expected:
                actual_major = actual.split(".")[0] if actual else ""
                expected_major = expected.split(".")[0] if expected else ""
                if actual_major != expected_major:
                    logger.warning(
                        "Installed Chrome %s differs from wafer's default "
                        "emulation Chrome %s; the TLS shape may diverge "
                        "(bump DEFAULT_EMULATION/_CHROME_BUILDS once wreq "
                        "ships this Chrome)",
                        actual,
                        expected,
                    )
                else:
                    logger.debug(
                        "Installed Chrome %s (wafer emulation is %s, "
                        "same major)",
                        actual,
                        expected,
                    )
            else:
                logger.debug(
                    "Validated exact Chrome %s executable at %s", actual, chrome
                )
            BrowserSolver._browser_installed.add(cache_key)
        finally:
            BrowserSolver._browser_install_lock.release()

    def _ensure_browser(self, deadline: float | None = None) -> None:
        """Launch browser if not running or if idle too long."""
        now = time.monotonic()

        if self._browser is not None:
            if self._last_used > 0 and (now - self._last_used) > self._idle_timeout:
                logger.debug(
                    "Browser idle timeout (%.0fs), closing",
                    now - self._last_used,
                )
                self._close_browser(preserve_identity=True)
            elif self._browser.is_connected():
                self._runtime_ready.set()
                return
            else:
                logger.debug("Browser disconnected, relaunching")
                self._close_browser(preserve_identity=True)

        try:
            from patchright.sync_api import sync_playwright
        except ImportError:
            raise ImportError(
                "patchright is required for browser solving. "
                "Install with: pip install wafer-py[browser]"
            ) from None

        self._ensure_browser_installed(deadline)
        if deadline is not None and time.monotonic() >= deadline:
            raise TimeoutError("Browser startup exceeded solve timeout")

        proxied = bool(self._proxy_server or self._egress_guard_proxy)

        try:
            logger.debug("Starting playwright driver...")
            with hardened_driver_env():
                self._playwright = sync_playwright().start()
            if deadline is not None and time.monotonic() >= deadline:
                raise TimeoutError("Playwright startup exceeded solve timeout")
            if self._headless and self._browser_ua is None:
                # The scrubbed UA has to be on the command line (see
                # hardened_launch_config), so read the real one from a first
                # launch. An idle relaunch keeps the UA it already has.
                self._launch_chromium(
                    hardened_launch_config(
                        headless=True,
                        proxied=proxied,
                        viewport=self._solver_viewport(),
                    ),
                    deadline,
                    offline=True,
                )
                self._browser_ua = scrub_headless_ua(self._read_browser_ua())
                self._browser.close()
                self._browser = None
            # Single source of truth, shared with callers driving their own
            # Playwright: see hardened_launch_config for why it is exported.
            self._launch_chromium(
                hardened_launch_config(
                    headless=self._headless,
                    proxied=proxied,
                    user_agent=self._browser_ua if self._headless else None,
                    viewport=self._solver_viewport(),
                ),
                deadline,
            )
        except Exception:
            self._close_browser(preserve_identity=True)
            raise

        try:
            launched_version = self._browser.version
            expected_version = self._expected_browser_version()
            if launched_version != expected_version:
                launched_major = launched_version.split(".")[0]
                expected_major = expected_version.split(".")[0]
                if launched_major != expected_major:
                    logger.warning(
                        "Launched Chrome %s differs from wafer's default "
                        "emulation Chrome %s; the TLS shape may diverge",
                        launched_version,
                        expected_version,
                    )
                else:
                    logger.debug(
                        "Launched Chrome %s (wafer emulation is %s, "
                        "same major)",
                        launched_version,
                        expected_version,
                    )

            # Capture the real Chrome full version (e.g. "145.0.7632.117")
            # for CDP metadata.  The UA string is reduced to MAJOR.0.0.0
            # so we can't extract the full version from there.
            # Keep one configured envelope across an idle/disconnect relaunch.
            # Existing HTTP sessions may already be pinned to it; republishing
            # a newly installed Chrome version would split that identity
            # mid-session.
            if self._browser_version is None:
                self._browser_version = launched_version

            if self._headless:
                # The relaunch must report exactly the UA it was given.
                # Anything else means the switch did not take, and every target
                # the page overrides cannot reach would announce
                # "HeadlessChrome".
                reported = self._read_browser_ua()
                if reported != self._browser_ua or "HeadlessChrome" in reported:
                    raise RuntimeError(
                        f"Headless Chrome reported {reported!r} after launching "
                        f"with --user-agent={self._browser_ua!r}"
                    )
        except Exception:
            # A browser that failed these checks must not survive to the next
            # call, which would find it connected and skip them.
            self._close_browser(preserve_identity=True)
            raise

        self._publish_browser_identity()
        self._runtime_ready.set()

        self._last_used = time.monotonic()
        logger.info("Browser launched (headless=%s)", self._headless)

    def _launch_chromium(
        self, launch_config: HardenedLaunch, deadline, *, offline: bool = False
    ) -> None:
        """Launch the pinned Chrome with *launch_config* into ``_browser``.

        *offline* cuts the browser off the network entirely, for a launch that
        only reads the browser's own user agent (see :data:`_OFFLINE_ARGS`).
        """
        logger.debug("Launching Chrome (headless=%s)...", self._headless)
        launch_timeout = 30000
        if deadline is not None:
            launch_timeout = min(
                launch_timeout,
                max(1, int((deadline - time.monotonic()) * 1000)),
            )
        launch_kwargs = {
            # ``channel='chrome'`` may resolve a different local binary
            # than the one validated above.  Pin the executable directly.
            "executable_path": self._browser_executable(),
            "headless": self._headless,
            "args": list(launch_config.args) + (_OFFLINE_ARGS if offline else []),
            "ignore_default_args": list(launch_config.ignore_default_args),
            "timeout": launch_timeout,
        }
        browser_proxy = self._egress_guard_proxy or self._proxy_server
        if browser_proxy and not offline:
            launch_kwargs["proxy"] = _playwright_proxy(browser_proxy)
        browser = self._playwright.chromium.launch(**launch_kwargs)
        self._browser = browser

        def _disconnected(*_args) -> None:
            # The UA probe's browser disconnecting late must not mark the
            # relaunched one unready.
            if self._browser is browser:
                self._runtime_ready.clear()

        browser.on("disconnected", _disconnected)
        if deadline is not None and time.monotonic() >= deadline:
            raise TimeoutError("Browser launch exceeded solve timeout")

    def _read_browser_ua(self) -> str:
        """The launched browser's own ``navigator.userAgent``, from about:blank."""
        probe = self._browser.new_page()
        try:
            raw_ua = probe.evaluate("navigator.userAgent")
        finally:
            # Without this the page leaks whenever evaluate() raises, and
            # the half-initialised browser is then handed to callers.
            try:
                probe.close()
            except Exception:
                logger.debug("Could not close UA probe page", exc_info=True)
        if not isinstance(raw_ua, str) or not raw_ua:
            # Fail loudly. Without a UA there is nothing to put on the
            # command line, and the browser then leaks "HeadlessChrome" on
            # every request -a silent degradation of the exact property this
            # probe exists to protect.
            raise RuntimeError(
                f"Browser did not report a user agent (got {raw_ua!r})"
            )
        return raw_ua

    def _capture_preflight_identity(self) -> None:
        """Capture headed Chrome's reduced UA without navigating anywhere."""

        if self._browser is None:
            return
        if self._browser_ua is not None:
            self._publish_browser_identity()
            return
        context = None
        try:
            # ``about:blank`` is local and creates no network traffic.  Use a
            # normal context so the observed UA is exactly what solves use.
            context = self._create_context()
            page = context.new_page()
            ua = page.evaluate("navigator.userAgent")
            if isinstance(ua, str) and ua:
                self._browser_ua = ua
                self._publish_browser_identity()
            else:
                logger.warning("Browser preflight did not return a user agent")
        finally:
            if context is not None:
                try:
                    context.close()
                except Exception:
                    logger.debug(
                        "Could not close browser preflight context",
                        exc_info=True,
                    )

    def _probe_screenxy_patch(self) -> None:
        """Measure CDP input coordinates before deciding whether to patch JS.

        Replacing native MouseEvent/PointerEvent descriptors is observable to
        challenge code, so it is permitted only when a real Patchright click
        proves this browser has Chromium's historical screen-coordinate bug.
        This uses an about:blank context and makes no network request.
        """

        if self._needs_screenxy_patch is not None:
            return
        context = None
        try:
            context = self._create_context()
            page = context.new_page()
            page.set_content(
                "<button id='probe' style='width:240px;height:240px'>probe</button>"
            )
            # Patchright's set_content does not reliably execute inline
            # scripts under headed Xvfb/JWM. Install the listener through the
            # page evaluation protocol, then exercise genuine mouse input.
            page.evaluate(
                "() => { window.__waferScreenXY=null;"
                "document.addEventListener('click', e => "
                "window.__waferScreenXY={clientX:e.clientX,clientY:e.clientY,"
                "screenX:e.screenX,screenY:e.screenY,windowX:window.screenX,"
                "windowY:window.screenY,chromeY:window.outerHeight-window.innerHeight},"
                "{once:true}); }"
            )
            page.mouse.click(100, 100)
            observed = page.evaluate("window.__waferScreenXY")
            if not isinstance(observed, dict):
                raise RuntimeError("Browser screen-coordinate probe produced no event")
            try:
                client_x = float(observed["clientX"])
                client_y = float(observed["clientY"])
                screen_x = float(observed["screenX"])
                screen_y = float(observed["screenY"])
                window_x = float(observed["windowX"])
                window_y = float(observed["windowY"])
                chrome_y = float(observed["chromeY"])
            except (KeyError, TypeError, ValueError) as exc:
                raise RuntimeError(
                    "Browser screen-coordinate probe returned invalid values"
                ) from exc
            if screen_x == client_x and screen_y == client_y:
                self._needs_screenxy_patch = True
                logger.warning("Browser requires screen-coordinate compatibility patch")
                return
            if (
                abs(screen_x - (client_x + window_x)) <= 1
                and abs(screen_y - (client_y + window_y + chrome_y)) <= 1
            ):
                self._needs_screenxy_patch = False
                logger.debug("Browser has native-correct screen coordinates")
                return
            # Neither shape matched. The coordinates are still offset from the
            # client origin (the broken case above is already excluded), so
            # only the magnitude is unexplained -- headless Chrome on macOS
            # reports an event screenY that window.screenY/outerHeight do not
            # account for. Do NOT fail the solver over it, and do NOT inject
            # the compatibility script: it is a Function.prototype.toString
            # visible override that only a positive probe may authorize.
            self._needs_screenxy_patch = False
            logger.warning(
                "Browser screen-coordinate probe was inconclusive "
                "(client=%s,%s screen=%s,%s window=%s,%s chrome_y=%s); "
                "leaving native coordinates unpatched",
                client_x,
                client_y,
                screen_x,
                screen_y,
                window_x,
                window_y,
                chrome_y,
            )
        finally:
            if context is not None:
                try:
                    context.close()
                except Exception:
                    logger.debug("Could not close screen-coordinate probe context")

    def _close_browser(self, *, preserve_identity: bool = False) -> None:
        """Shut down browser and playwright."""
        self._runtime_ready.clear()
        unbind_page()
        if self._browser:
            try:
                self._browser.close()
            except Exception:
                pass
            self._browser = None
        if self._playwright:
            try:
                self._playwright.stop()
            except Exception:
                pass
            self._playwright = None
        if not preserve_identity:
            self._browser_ua = None
            self._browser_version = None
            self._clear_browser_identity()

    def _solver_viewport(self) -> tuple[int, int] | None:
        """The headless macOS page size: one per solver, fitting the display."""
        if not self._headless or sys.platform != "darwin":
            return None
        if self._viewport is None:
            screen = _host_screen()
            self._viewport = random.choice(
                _fitting_viewports(screen) or [_default_viewport(screen)]
            )
        return self._viewport

    def _create_context(self):
        """Create a new browser context with realistic settings."""
        kwargs: dict = {}
        if self._headless and sys.platform == "darwin":
            # The launch sized the window and described the real display
            # (hardened_launch_config), so the browser's own geometry is
            # headed Chrome's: no viewport emulation, which would replace the
            # screen with the viewport and drop the menu bar and Dock.
            kwargs["no_viewport"] = True
        elif self._headless:
            # Headless has no real window, so we must set a viewport
            # and DPR explicitly.
            viewport = random.choice(_VIEWPORTS)
            kwargs["viewport"] = {
                "width": viewport[0],
                "height": viewport[1],
            }
            # macOS Retina displays are always DPR 2.  Non-Retina
            # Macs are extinct.  Linux/Windows default to 1.
            dpr = 2 if sys.platform == "darwin" else 1
            kwargs["device_scale_factor"] = dpr
        else:
            # Headed: let the browser use its natural window size.
            # Forcing a viewport larger than the screen causes
            # innerHeight > outerHeight, which is impossible in a
            # real browser and detected by DataDome.  The real
            # display's DPR is already correct.
            kwargs["no_viewport"] = True
        # No context-level user_agent. The headless launch carries the
        # scrubbed UA as --user-agent, and _setup_headless_patches overrides
        # it with full client-hint metadata on every page, iframe and worker.
        # A context-level one only adds Playwright's own metadata, which
        # reports architecture x86 and platformVersion 10.15.7 in every
        # cross-site iframe whatever the host.
        return self._browser.new_context(**kwargs)

    @staticmethod
    def _bounded_page_content(page, max_size: int | None) -> str:
        """Serialize the DOM only when it fits the caller's response budget."""

        try:
            if max_size is None:
                return page.content()
            char_length = _quiet_read(page, _DOCUMENT_LENGTH)
            if not isinstance(char_length, (int, float)):
                return ""
            if char_length <= 0 or char_length > max_size:
                return ""
            html = page.content()
            if len(html.encode("utf-8")) > max_size:
                return ""
            return html
        except Exception:
            return ""

    @staticmethod
    def _install_navigation_size_limit(page, max_size: int | None) -> dict[str, object]:
        """Stop an oversized main-document transfer before it is downloaded.

        The DOM serialization check runs after navigation and therefore cannot
        protect memory or bandwidth while Chrome is receiving the response.
        CDP reports decoded and encoded byte deltas for each request, allowing
        the main document to be stopped as soon as either representation
        exceeds the response budget.
        """

        state: dict[str, object] = {
            "exceeded": False,
            "documents": set(),
            "sizes": {},
            "size": 0,
            "main_frame_id": None,
        }
        if max_size is None:
            return state

        limit = max_size
        cdp = page.context.new_cdp_session(page)
        cdp.send("Network.enable")
        try:
            frame_tree = cdp.send("Page.getFrameTree")
            if isinstance(frame_tree, dict):
                frame = frame_tree.get("frameTree", {}).get("frame", {})
                frame_id = frame.get("id") if isinstance(frame, dict) else None
                if isinstance(frame_id, str) and frame_id:
                    state["main_frame_id"] = frame_id
        except Exception:
            # The post-navigation DOM check still enforces the cap. Avoid
            # guessing that an iframe is the main response when frame identity
            # is unavailable.
            logger.debug(
                "Could not resolve browser main-frame identity",
                exc_info=True,
            )

        def stop_loading(observed_size: int) -> None:
            if state["exceeded"]:
                return
            state["size"] = observed_size
            state["exceeded"] = True
            try:
                cdp.send("Page.stopLoading")
            except Exception:
                logger.debug(
                    "Could not stop oversized browser navigation",
                    exc_info=True,
                )

        def request_started(params: dict) -> None:
            if params.get("type") != "Document":
                return
            request_id = params.get("requestId")
            if not request_id:
                return
            main_frame_id = state["main_frame_id"]
            frame_id = params.get("frameId")
            if main_frame_id is not None and frame_id != main_frame_id:
                return
            if main_frame_id is None and frame_id is not None:
                # Real CDP events always identify their frame. If the frame-tree
                # query failed, do not guess which identified frame is top-level;
                # the post-navigation DOM check remains authoritative. Events
                # without frameId are retained as a compatibility fallback for
                # older/mocked protocol implementations.
                return
            documents = state["documents"]
            sizes = state["sizes"]
            assert isinstance(documents, set)
            assert isinstance(sizes, dict)
            # With an authoritative frame ID, track every main-frame navigation:
            # WAF challenge pages frequently auto-reload into the final response
            # under a new request ID. Only the unknown-frame compatibility
            # fallback is restricted to its first Document.
            if main_frame_id is None and documents:
                return
            documents.add(request_id)
            sizes.setdefault(request_id, {"decoded": 0, "encoded": 0})

        def response_received(params: dict) -> None:
            request_id = params.get("requestId")
            documents = state["documents"]
            assert isinstance(documents, set)
            if request_id not in documents:
                return
            headers = params.get("response", {}).get("headers", {})
            for key, value in headers.items():
                if str(key).lower() != "content-length":
                    continue
                try:
                    declared = int(value)
                    if declared > limit:
                        stop_loading(declared)
                except (TypeError, ValueError):
                    pass
                break

        def data_received(params: dict) -> None:
            request_id = params.get("requestId")
            documents = state["documents"]
            sizes = state["sizes"]
            assert isinstance(documents, set)
            assert isinstance(sizes, dict)
            if request_id not in documents or state["exceeded"]:
                return
            totals = sizes.setdefault(request_id, {"decoded": 0, "encoded": 0})
            try:
                decoded = max(int(params.get("dataLength", 0) or 0), 0)
            except (TypeError, ValueError):
                decoded = 0
            try:
                encoded = max(int(params.get("encodedDataLength", 0) or 0), 0)
            except (TypeError, ValueError):
                encoded = 0
            totals["decoded"] += decoded
            totals["encoded"] += encoded
            observed = max(totals["decoded"], totals["encoded"])
            state["size"] = observed
            if observed > limit:
                stop_loading(observed)

        cdp.on("Network.requestWillBeSent", request_started)
        cdp.on("Network.responseReceived", response_received)
        cdp.on("Network.dataReceived", data_received)
        return state

    def _install_init_script_fallback(self, page, scripts: list, cdp) -> None:
        """See :func:`_install_init_script_fallback`."""
        _install_init_script_fallback(page, scripts, cdp)

    def _verify_headless_patches(self, page) -> None:
        """Warn when the registered init scripts did not actually run.

        ``Page.addScriptToEvaluateOnNewDocument`` returns an identifier and
        then silently never executes under some Patchright builds, which
        makes every fingerprint patch below a no-op. Headed Chrome does not
        care -- its values are already native-correct -- but headless keeps
        ``outerWidth == innerWidth`` and ``colorDepth == 24``, which is a
        plain headless signature. Surface it once per page instead of letting
        a solve fail for reasons nothing logs.
        """

        if not self._headless or getattr(page, "_wafer_patch_checked", False):
            return
        page._wafer_patch_checked = True  # type: ignore[attr-defined]
        # Kasada and Akamai pages get no window patch on purpose (see
        # _setup_headless_patches), so their colorDepth 24 is no failure to
        # report. Logged as one, it sent a chewy.com Akamai solve's debugging
        # after an init script that was never registered (2026-10-06).
        if getattr(page, "_wafer_window_patch", True) is False:
            return
        try:
            state = _quiet_read(
                page, "[window.outerWidth, window.innerWidth, screen.colorDepth]"
            )
            outer, inner, depth = state
        except Exception:
            return
        if outer == inner or depth == 24:
            logger.warning(
                "Headless fingerprint patches did not apply "
                "(outerWidth=%s innerWidth=%s colorDepth=%s); the CDP init "
                "script registered but never ran, so this browser is "
                "identifiable as headless. Prefer headless=False for "
                "challenge solving.",
                outer,
                inner,
                depth,
            )

    def _setup_headless_patches(
        self,
        page,
        *,
        challenge_type: str | None = None,
    ) -> None:
        """Register fingerprint patches via CDP.

        Must be called after page creation but before navigation. The commands
        come from :func:`_page_hardening_commands`, the same source
        :func:`harden_page` uses; only the script set is the solver's own.

        **All modes** (headed + headless):
        - ``Emulation.setUserAgentOverride`` with ``userAgentMetadata`` and
          ``acceptLanguage``, so ``sec-ch-ua``, ``navigator.userAgentData``
          and ``navigator.languages`` agree with the user agent.
        - The screenX/screenY fix for the CDP mouse event bug
          (Chromium #40280325), when the real-input probe proved it.

        **Headless only** (additional):
        - The headless fingerprint fix script (colorDepth, outerWidth,
          outerHeight, screenY patches for macOS), with one geometry for the
          page and its iframes, only when the page does not already report
          the launch's real display (``_native_window``; a ``no_viewport``
          macOS context does, natively). Also skipped for Kasada and Akamai,
          whose challenge JS detects its Function.prototype.toString wrapper.
        - ``color-gamut: p3`` on macOS.

        Every iframe and worker the page starts is attached paused and given
        the same scripts and user-agent override before it runs; see
        :func:`_child_target_commands`.
        """
        # Guard against double registration (each call creates a new
        # CDP session and re-registers the init script).
        if getattr(page, "_wafer_headless_patched", False):
            return
        page._wafer_headless_patched = True  # type: ignore[attr-defined]
        cdp = page.context.new_cdp_session(page)

        # Registered through CDP and re-applied on navigation by
        # _install_init_script_fallback, since the CDP registration can be
        # accepted and never executed.
        scripts = []

        # Native-correct Chrome keeps its original event descriptors. Only a
        # real-input probe can authorize the compatibility replacement.
        if self._needs_screenxy_patch:
            scripts.append(_SCREENXY_FIX_SCRIPT)

        # Kasada's ips.js and Akamai's behavioral challenge JS detect the
        # Function.prototype.toString wrapper in _HEADLESS_FIX_SCRIPT. Kasada
        # withholds x-kpsdk-r; Akamai behavioral refuses to set session
        # cookies. scrgb-linear alone handles the CSS cross-checks.
        # A page already showing the launch's real display needs no window
        # script, and then Kasada and Akamai pages get the same fidelity as
        # any other instead of going without.
        native = False
        if self._headless:
            try:
                state = cdp.send(
                    "Runtime.evaluate",
                    {"expression": _WINDOW_STATE, "returnByValue": True},
                )
                native = _native_window(state.get("result", {}).get("value"))
            except Exception:
                logger.debug("Could not read the window state", exc_info=True)
        window_patch = (
            self._headless
            and not native
            and challenge_type not in ("kasada", "akamai")
        )
        page._wafer_window_patch = window_patch  # type: ignore[attr-defined]
        page._wafer_native_window = native  # type: ignore[attr-defined]
        if window_patch:
            scripts.extend(
                _page_scripts(True, _viewport_of(page.viewport_size))
            )

        if self._headless:
            ua = self._browser_ua
            if not ua:
                # _ensure_browser sets it before any headless page exists.
                # Without it there is no override, and every frame and worker
                # would keep the launch's low-entropy client hints.
                raise RuntimeError("Headless solver page has no user agent")
        else:
            ua = self._browser_ua or page.evaluate("navigator.userAgent")
        ua_params = _ua_override_params(ua, self._browser_version) if ua else None
        # The pages the driver sets up itself, popups included, start with it.
        _publish_ua_override(ua, ua_params)

        # Do NOT detach the CDP session - that removes registered
        # scripts.  GC-safe: Playwright's channel registry keeps it
        # alive for the page's lifetime.
        _apply_page_hardening(
            page,
            cdp,
            headless=self._headless,
            ua_params=ua_params,
            scripts=scripts,
            browser=self._browser,
        )
        _harden_popups(page, self._setup_headless_patches)
        # Its iframes and workers are now attached paused and released by
        # this thread's CDP events; solver sleeps deliver them through idle().
        bind_page(page)

    # ------------------------------------------------------------------
    # Recording loader
    # ------------------------------------------------------------------

    def _ensure_recordings(self) -> bool:
        """Lazy-load human mouse recordings on first PX encounter.

        Returns True if all required categories (idles, paths, holds)
        have at least one recording.  Caches results so subsequent
        calls are free.
        """
        if self._idle_recordings is not None:
            return bool(
                self._idle_recordings
                and self._path_recordings
                and self._hold_recordings
            )

        self._idle_recordings = []
        self._path_recordings = []
        self._hold_recordings = []
        self._drag_recordings = []
        self._slide_recordings = []
        self._browse_recordings = []
        self._grid_recordings = []

        try:
            rec_dir = importlib.resources.files("wafer.browser") / "_recordings"
        except Exception:
            logger.debug("Recordings package not found")
            return False

        # --- idles ---
        try:
            for f in (rec_dir / "idles").iterdir():
                name = str(f).rsplit("/", 1)[-1]
                if not name.endswith(".csv"):
                    continue
                text = f.read_text()
                rows = _parse_csv_rows(text, ("t", "dx", "dy"))
                if rows:
                    self._idle_recordings.append({"rows": rows, "name": name})
        except Exception:
            logger.debug("Failed to load idle recordings", exc_info=True)

        # --- paths ---
        try:
            for f in (rec_dir / "paths").iterdir():
                name = str(f).rsplit("/", 1)[-1]
                if not name.endswith(".csv"):
                    continue
                text = f.read_text()
                meta = _parse_metadata(text.splitlines()[0])
                angle = _angle_from_metadata(meta)
                rows = _parse_csv_rows(text, ("t", "rx", "ry"))
                if rows:
                    self._path_recordings.append(
                        {
                            "rows": rows,
                            "angle": angle,
                            "meta": meta,
                            "name": name,
                        }
                    )
        except Exception:
            logger.debug("Failed to load path recordings", exc_info=True)

        # --- holds ---
        try:
            for f in (rec_dir / "holds").iterdir():
                name = str(f).rsplit("/", 1)[-1]
                if not name.endswith(".csv"):
                    continue
                text = f.read_text()
                rows = _parse_csv_rows(text, ("t", "dx", "dy"))
                if rows:
                    self._hold_recordings.append({"rows": rows, "name": name})
        except Exception:
            logger.debug("Failed to load hold recordings", exc_info=True)

        # --- drags ---
        try:
            for f in (rec_dir / "drags").iterdir():
                name = str(f).rsplit("/", 1)[-1]
                if not name.endswith(".csv"):
                    continue
                text = f.read_text()
                meta = _parse_metadata(text.splitlines()[0])
                rows = _parse_csv_rows(text, ("t", "rx", "ry"))
                if rows:
                    self._drag_recordings.append(
                        {"rows": rows, "meta": meta, "name": name}
                    )
        except Exception:
            logger.debug("Failed to load drag recordings", exc_info=True)

        # --- slide_drags (full-width "slide to verify" drags) ---
        try:
            for f in (rec_dir / "slide_drags").iterdir():
                name = str(f).rsplit("/", 1)[-1]
                if not name.endswith(".csv"):
                    continue
                text = f.read_text()
                meta = _parse_metadata(text.splitlines()[0])
                rows = _parse_csv_rows(text, ("t", "rx", "ry"))
                if rows:
                    self._slide_recordings.append(
                        {"rows": rows, "meta": meta, "name": name}
                    )
        except Exception:
            logger.debug("Failed to load slide recordings", exc_info=True)

        # --- browses ---
        try:
            for f in (rec_dir / "browses").iterdir():
                name = str(f).rsplit("/", 1)[-1]
                if not name.endswith(".csv"):
                    continue
                text = f.read_text()
                meta = _parse_metadata(text.splitlines()[0])
                rows = _parse_csv_rows(text, ("t", "dx", "dy", "scroll_y"))
                if rows:
                    self._browse_recordings.append(
                        {
                            "rows": rows,
                            "max_scroll": int(meta.get("max_scroll", "0")),
                            "sections": int(meta.get("sections", "0")),
                            "name": name,
                        }
                    )
        except Exception:
            logger.debug("Failed to load browse recordings", exc_info=True)

        # --- grids (short-hop paths for tile clicking) ---
        try:
            for f in (rec_dir / "grids").iterdir():
                name = str(f).rsplit("/", 1)[-1]
                if not name.endswith(".csv"):
                    continue
                text = f.read_text()
                meta = _parse_metadata(text.splitlines()[0])
                angle = _angle_from_metadata(meta)
                rows = _parse_csv_rows(text, ("t", "rx", "ry"))
                if rows:
                    self._grid_recordings.append(
                        {
                            "rows": rows,
                            "angle": angle,
                            "meta": meta,
                            "name": name,
                        }
                    )
        except Exception:
            logger.debug("Failed to load grid recordings", exc_info=True)

        logger.info(
            "Loaded %d idle + %d path + %d hold + %d drag"
            " + %d slide + %d grid + %d browse recordings",
            len(self._idle_recordings),
            len(self._path_recordings),
            len(self._hold_recordings),
            len(self._drag_recordings),
            len(self._slide_recordings),
            len(self._grid_recordings),
            len(self._browse_recordings),
        )
        return bool(
            self._idle_recordings and self._path_recordings and self._hold_recordings
        )

    # ------------------------------------------------------------------
    # Mouse replay methods (shared by PX and future drag solvers)
    # ------------------------------------------------------------------

    def _pick_path(
        self,
        start_x: float,
        start_y: float,
        target_x: float,
        target_y: float,
        pool: list[dict] | None = None,
    ) -> dict:
        """Pick a recorded path whose direction best matches the move."""
        recordings = pool if pool is not None else self._path_recordings
        angle = math.atan2(target_y - start_y, target_x - start_x)

        def _angle_diff(rec: dict) -> float:
            diff = abs(rec["angle"] - angle)
            return min(diff, 2 * math.pi - diff)

        best = min(recordings, key=_angle_diff)
        return best

    def _replay_idle(
        self, page, origin_x: float, origin_y: float
    ) -> tuple[float, float]:
        """Replay recorded idle mouse movement.

        Returns the final ``(x, y)`` position.
        """
        rec = random.choice(self._idle_recordings)
        recording = rec["rows"]
        time_scale = random.uniform(0.85, 1.15)
        duration = recording[-1]["t"] * time_scale if recording else 0

        logger.info(
            "Idle: %s (%.1fs, %d points) from (%.0f, %.0f)",
            rec["name"],
            duration,
            len(recording),
            origin_x,
            origin_y,
        )

        page.mouse.move(origin_x, origin_y)
        t0 = time.monotonic()
        final_x, final_y = origin_x, origin_y

        for row in recording:
            target_t = row["t"] * time_scale
            elapsed = time.monotonic() - t0
            delay = target_t - elapsed
            if delay > 0:
                idle(delay)

            final_x = origin_x + row["dx"]
            final_y = origin_y + row["dy"]
            page.mouse.move(final_x, final_y)

        return final_x, final_y

    def _replay_path(
        self,
        page,
        start_x: float,
        start_y: float,
        target_x: float,
        target_y: float,
        pool: list[dict] | None = None,
        deadline: float | None = None,
    ) -> bool:
        """Replay a recorded human path from start to target."""
        rec = self._pick_path(start_x, start_y, target_x, target_y, pool=pool)
        recording = rec["rows"]
        dx = target_x - start_x
        dy = target_y - start_y
        time_scale = random.uniform(0.85, 1.15)
        duration = recording[-1]["t"] * time_scale if recording else 0

        logger.info(
            "Path: %s (%s, %.1fs, %d points) (%.0f,%.0f) -> (%.0f,%.0f)",
            rec["name"],
            rec["meta"].get("direction", "?"),
            duration,
            len(recording),
            start_x,
            start_y,
            target_x,
            target_y,
        )

        page.mouse.move(start_x, start_y)
        t0 = time.monotonic()

        for row in recording:
            if deadline is not None and time.monotonic() >= deadline:
                return False
            target_t = row["t"] * time_scale
            elapsed = time.monotonic() - t0
            delay = target_t - elapsed
            if delay > 0:
                if deadline is not None:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        return False
                    idle(min(delay, remaining))
                    if delay >= remaining:
                        return False
                else:
                    idle(delay)

            x = start_x + row["rx"] * dx
            y = start_y + row["ry"] * dy
            page.mouse.move(x, y)
        return True

    def _replay_drag(
        self,
        page,
        start_x: float,
        start_y: float,
        end_x: float,
        end_y: float,
        deadline: float | None = None,
        telemetry_label: str | None = None,
        exclude_recordings: set[str] | None = None,
        recording_pool_size: int = 3,
        approach_from: tuple[float, float] | None = None,
        full_track_slide: bool = False,
    ) -> bool:
        """Replay a recorded drag from start to end.

        Recordings include an optional pre-drag hover phase (natural
        pause near the handle before clicking).  The ``mousedown_t``
        metadata field marks when the click happens — events before it
        are replayed as cursor movement without the button held.

        When ``approach_from`` is supplied, the approach path terminates at
        the recording's *first hover point*.  Terminating at the eventual
        mousedown point instead would make recordings whose hover begins a
        few pixels away teleport from the handle to their first sample.

        The recording's ``ry`` values are normalized against the original
        horizontal track width (not vertical displacement).  This preserves
        natural vertical wobble even for perfectly horizontal drags where
        ``end_y ≈ start_y``.
        """
        dx = end_x - start_x
        target_dist = abs(dx)

        # Pick recording with closest original drag distance — a 50px
        # drag has a fundamentally different speed/deceleration profile
        # than a 300px drag, so matching distance keeps it natural.
        def _drag_dist(rec: dict) -> float:
            meta = rec.get("meta", {})
            if "start" in meta and "end" in meta:
                try:
                    sx, _ = meta["start"].split(",")
                    ex, _ = meta["end"].split(",")
                    return abs(int(ex) - int(sx))
                except (ValueError, IndexError):
                    pass
            return 0.0

        # Sort by distance similarity. Generic drags use the closest three
        # traces; a full-width slider can request its complete bounded slide
        # corpus to avoid replaying nearly identical trajectories after a
        # challenge retry.
        ranked = sorted(
            self._drag_recordings,
            key=lambda r: abs(_drag_dist(r) - target_dist),
        )
        pool_size = max(1, int(recording_pool_size))
        pool = ranked[: min(pool_size, len(ranked))]
        if exclude_recordings:
            unused = [
                recording
                for recording in pool
                if recording.get("name") not in exclude_recordings
            ]
            if unused:
                pool = unused
        recording = random.choice(pool)
        self._last_drag_recording_name = recording.get("name")
        rows = recording["rows"]
        if not rows:
            return False
        meta = recording.get("meta", {})
        mousedown_t = float(meta.get("mousedown_t", "0"))
        time_scale = random.uniform(0.85, 1.15)

        # A "slide to verify" drag is a confident flick, not the careful creep
        # a puzzle drag needs.  A human slide captured on the live Alibaba
        # widget crossed the 258px track in 0.76s (421px/s) emitting 34 moves
        # (44/s); the shipped slide corpus runs 3.07-5.42s (48-84px/s), so
        # replaying it natively is ~7x too slow.  mousse's own recording
        # instructions call for "confident and fast", so treat the corpus
        # timing as mis-recorded and normalize the *pressed* phase to human
        # slide speed.  The pre-mousedown hover is left alone: that is
        # deliberate thinking time and the human's was a comparable ~1s.
        #
        # Subsampling is not cosmetic.  CDP move dispatch costs ~8-10ms, so a
        # 250-event drag cannot physically be emitted in 0.76s; without
        # dropping events the compression would silently not happen.
        drag_scale = time_scale
        keep_every = 1
        if full_track_slide:
            native_drag = rows[-1]["t"] - mousedown_t
            pressed_rows = sum(1 for row in rows if row["t"] >= mousedown_t)
            if native_drag > 0 and pressed_rows > 2:
                target_drag = random.uniform(*_SLIDE_DRAG_SECONDS)
                drag_scale = target_drag / native_drag
                target_events = max(
                    2, int(target_drag * random.uniform(*_SLIDE_EVENT_RATE))
                )
                keep_every = max(1, round(pressed_rows / target_events))
        if telemetry_label is not None:
            # Recording filenames and timing contain no page/request content.
            logger.info(
                "%s drag trace: recording=%s time_scale=%.3f "
                "drag_scale=%.3f keep_every=%d",
                telemetry_label,
                recording.get("name", "unknown"),
                time_scale,
                drag_scale,
                keep_every,
            )

        first = rows[0]
        first_x = start_x + first["rx"] * dx
        first_y = start_y + first["ry"] * abs(dx)
        if approach_from is not None:
            if not self._replay_path(
                page,
                approach_from[0],
                approach_from[1],
                first_x,
                first_y,
                deadline=deadline,
            ):
                return False
        else:
            page.mouse.move(first_x, first_y)

        t0 = time.monotonic()
        mouse_down = False
        # The first row is the initial cursor sample.  Positioning above
        # already emitted it, so replay subsequent samples only.  A recording
        # that presses at t=0 still needs its button transition at this point.
        if first["t"] >= mousedown_t:
            page.mouse.down()
            mouse_down = True

        rest = rows[1:]
        last_index = len(rest) - 1
        pressed_seen = 0
        try:
            for index, row in enumerate(rest):
                if deadline is not None and time.monotonic() >= deadline:
                    return False

                pressed = row["t"] >= mousedown_t
                if pressed:
                    pressed_seen += 1
                    # Never drop the row that carries the button transition or
                    # the final sample: one owns the mousedown coordinate, the
                    # other owns the release.
                    if (
                        keep_every > 1
                        and mouse_down
                        and index != last_index
                        and pressed_seen % keep_every
                    ):
                        continue

                # Compress only the pressed phase; the hover keeps its own
                # recorded pacing.
                if pressed:
                    target_t = (
                        mousedown_t * time_scale
                        + (row["t"] - mousedown_t) * drag_scale
                    )
                else:
                    target_t = row["t"] * time_scale
                elapsed = time.monotonic() - t0
                delay = target_t - elapsed
                if delay > 0:
                    if deadline is not None:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            return False
                        idle(min(delay, remaining))
                        if delay >= remaining:
                            return False
                    else:
                        idle(delay)

                x = start_x + row["rx"] * dx
                y = start_y + row["ry"] * abs(dx)
                if mouse_down and not full_track_slide:
                    # A placement drag must land where the caller aimed.
                    # ``end_x`` is a CV-computed notch offset (GeeTest) with no
                    # physical stop, and 6 of the 26 shipped puzzle recordings
                    # release past their own target -- up to rx=1.074 -- so
                    # replaying that overshoot would drop the piece past the
                    # notch.  Constrain the pressed pointer to the interval.
                    #
                    # A full-track slide is the opposite case and is exempt:
                    # its handle pins at the track maximum, so overshoot only
                    # changes the pointer trace, and erasing it removed
                    # behavioral signal 3 in docs/ref-baxia.md.  The human
                    # slide accepted by Baxia on 2026-07-31 released at
                    # rx=1.26, 64px beyond full travel.
                    x = min(max(x, min(start_x, end_x)), max(start_x, end_x))
                page.mouse.move(x, y)
                # A recorded mousedown row is a button event at its recorded
                # cursor coordinate.  Moving and waiting must happen before
                # the button transition; pressing before the row's timestamp
                # creates an artificial stationary hold of up to hundreds of
                # milliseconds.
                if not mouse_down and row["t"] >= mousedown_t:
                    page.mouse.down()
                    mouse_down = True

            if not mouse_down:
                page.mouse.down()
                mouse_down = True
            return True
        finally:
            if mouse_down:
                page.mouse.up()

    # ------------------------------------------------------------------
    # Browse replay (background mouse/scroll during solver waits)
    # ------------------------------------------------------------------

    def _start_browse(
        self,
        page,
        origin_x: float,
        origin_y: float,
    ) -> _BrowseState | None:
        """Begin a browse recording for replay during solver waits.

        Returns a ``_BrowseState`` to pass to ``_replay_browse_chunk()``,
        or ``None`` if no browse recordings are available.
        """
        if self._browse_recordings is None:
            self._ensure_recordings()
        if not self._browse_recordings:
            return None

        rec = random.choice(self._browse_recordings)
        scroll_scale = 1.0
        time_scale = random.uniform(0.85, 1.15)

        logger.debug(
            "Browse: %s (%d points, scale=%.2f) from (%.0f, %.0f)",
            rec.get("name", "?"),
            len(rec["rows"]),
            time_scale,
            origin_x,
            origin_y,
        )

        try:
            page.mouse.move(origin_x, origin_y)
        except Exception:
            pass

        return _BrowseState(
            rows=rec["rows"],
            index=0,
            time_scale=time_scale,
            origin_x=origin_x,
            origin_y=origin_y,
            scroll_scale=scroll_scale,
            current_x=origin_x,
            current_y=origin_y,
        )

    def _replay_browse_chunk(
        self,
        page,
        state: _BrowseState | None,
        duration: float,
    ) -> None:
        """Replay a chunk of browse recording for *duration* seconds.

        Falls back to ``idle(duration)`` when *state* is ``None``
        or the recording is exhausted.
        """
        if state is None or state.index >= len(state.rows):
            idle(duration)
            return

        deadline = time.monotonic() + duration
        prev_t = (
            state.rows[state.index - 1]["t"]
            if state.index > 0
            else state.rows[state.index]["t"]
        )

        while state.index < len(state.rows):
            now = time.monotonic()
            if now >= deadline:
                break

            row = state.rows[state.index]
            delay = (row["t"] - prev_t) * state.time_scale
            if delay > 0:
                remaining = deadline - now
                if delay > remaining:
                    idle(remaining)
                    break
                idle(delay)

            x = state.origin_x + row["dx"]
            y = state.origin_y + row["dy"]
            try:
                page.mouse.move(x, y)
            except Exception:
                break

            scroll_y = row.get("scroll_y", 0)
            if scroll_y:
                try:
                    page.mouse.wheel(0, scroll_y * state.scroll_scale)
                except Exception:
                    pass

            state.current_x = x
            state.current_y = y
            prev_t = row["t"]
            state.index += 1

        # If recording exhausted before duration, sleep remainder
        remaining = deadline - time.monotonic()
        if remaining > 0:
            idle(remaining)

    # ------------------------------------------------------------------
    # PX convenience wrappers (delegate to _perimeterx module)
    # ------------------------------------------------------------------

    def _has_px_challenge(self, page) -> bool:
        from wafer.browser._perimeterx import has_px_challenge

        return has_px_challenge(page)

    def _find_px_button(self, page, timeout: float = 30.0):
        from wafer.browser._perimeterx import find_px_button

        return find_px_button(page, timeout)

    def _solve_perimeterx(self, page, timeout_ms: int) -> bool:
        from wafer.browser._perimeterx import solve_perimeterx

        return solve_perimeterx(self, page, timeout_ms)

    # ------------------------------------------------------------------
    # Solve dispatch
    # ------------------------------------------------------------------

    def _submit_on_worker(self, callback, *args, **kwargs):
        with self._executor_lock:
            if self._executor_closed:
                raise RuntimeError("BrowserSolver is closed")

            def invoke():
                self._worker_ident = threading.get_ident()
                return callback(*args, **kwargs)

            return self._executor.submit(invoke)

    def _run_on_worker(self, callback, *args, **kwargs):
        """Run a Patchright operation on this solver's owning thread."""

        if threading.get_ident() == self._worker_ident:
            return callback(*args, **kwargs)
        return self._submit_on_worker(callback, *args, **kwargs).result()

    def _mark_worker_recovering(self, future) -> None:
        """Make readiness honest until a timed-out worker operation returns."""

        self._runtime_ready.clear()

        def operation_finished(_future) -> None:
            with self._executor_lock:
                if self._executor_closed:
                    return
            try:
                connected = self._browser is not None and self._browser.is_connected()
            except Exception:
                connected = False
            if connected:
                self._runtime_ready.set()
            else:
                self._runtime_ready.clear()

        future.add_done_callback(operation_finished)

    def _interrupt_playwright_transport(self) -> bool:
        """Break a stuck sync protocol call so the serial worker can recover.

        Playwright's sync API exposes no timeout for operations such as
        ``BrowserContext.cookies``. SIGTERM to its private driver does not end
        the driver: once a browser is launched the driver handles SIGTERM by
        closing Chrome gracefully and stays up. That disconnects the browser,
        so a call waiting on it fails and returns; the owning worker then
        cleans up and ``_ensure_browser`` stops this driver and starts a fresh
        one on the next operation. Never escalate to SIGKILL: a dead driver
        ends the sync dispatcher greenlet, and every pending call then spins
        at 100% CPU forever instead of returning (measured 2026-10-05).
        """

        try:
            connection = self._playwright._impl_obj._connection
            process = connection._transport._proc
            if process.returncode is not None:
                return False
            process.terminate()
            return True
        except Exception:
            return False

    def _recover_timed_out_worker(self, future) -> None:
        if future.done():
            return
        self._mark_worker_recovering(future)
        interrupted = self._interrupt_playwright_transport()
        logger.warning(
            "Browser worker recovery requested (driver_interrupted=%s)",
            interrupted,
        )

    def preflight(self) -> None:
        """Launch Chrome on the solver worker to verify runtime readiness."""

        self._run_on_worker(self._preflight_on_worker)

    def _preflight_on_worker(self) -> None:
        with self._lock:
            self._ensure_browser()
            self._capture_preflight_identity()
            self._probe_screenxy_patch()

    def solve(
        self,
        url: str,
        challenge_type: str | None = None,
        timeout: float | None = None,
        embedder: str | None = None,
        replay: dict | None = None,
        max_size: int | None = None,
    ) -> SolveResult | None:
        """Solve on the dedicated worker within one end-to-end deadline."""

        if threading.get_ident() == self._worker_ident:
            return self._solve_on_worker(
                url,
                challenge_type,
                timeout,
                embedder,
                replay,
                max_size,
            )
        if not _valid_browser_url(url) or (
            embedder is not None and not _valid_browser_url(embedder)
        ):
            logger.warning("Refusing invalid browser navigation target")
            return None
        solve_timeout = self._solve_timeout if timeout is None else timeout
        if solve_timeout <= 0:
            return None
        deadline = time.monotonic() + solve_timeout
        future = self._submit_on_worker(
            self._solve_on_worker,
            url,
            challenge_type,
            solve_timeout,
            embedder,
            replay,
            max_size,
            _deadline=deadline,
        )
        try:
            return future.result(timeout=solve_timeout)
        except FutureTimeoutError:
            cancelled = future.cancel()
            if not cancelled and not future.done():
                self._recover_timed_out_worker(future)
            logger.warning(
                "Browser solve timed out after %.1fs (challenge_type=%s)",
                solve_timeout,
                challenge_type or "unknown",
            )
            return None

    def _solve_on_worker(
        self,
        url: str,
        challenge_type: str | None = None,
        timeout: float | None = None,
        embedder: str | None = None,
        replay: dict | None = None,
        max_size: int | None = None,
        *,
        _deadline: float | None = None,
    ) -> SolveResult | None:
        """Solve a WAF challenge by navigating in a real browser.

        Returns SolveResult with cookies and user_agent, or None on
        failure.

        ``embedder``: a same-site origin page to navigate instead of ``url``
        itself. Two sources feed it:

        - Imperva's auto-derived embedder (``imperva_embedder``): Imperva
          serves a top-level navigation to an API host its interactive
          "Error 15" block; loading the real origin page earns the
          registrable-domain reese84 / incap cookies, which then replay to
          the API host. This drives the specialized Imperva replay branch.
        - A session-level ``solve_origin`` (any challenge type): the request
          ``url`` is a JSON/XHR API that can't be top-navigated, but the WAF
          token is mintable on the site's origin page. For non-Imperva
          challenges the solver navigates ``embedder`` and runs the normal
          per-WAF dispatch there; the earned cookies replay to the API host.

        ``replay`` (Imperva embedder only): ``{method, body, content_type}``
        of the original request. After earning cookies on the embedder, the
        solve replays it as a same-site XHR from that page and returns the
        response as a passthrough using the body bytes returned by the browser.
        """
        if not _valid_browser_url(url) or (
            embedder is not None and not _valid_browser_url(embedder)
        ):
            logger.warning("Refusing invalid browser navigation target")
            return None
        if timeout is None:
            timeout = self._solve_timeout
        overall_deadline = (
            _deadline if _deadline is not None else time.monotonic() + timeout
        )
        timeout = min(timeout, overall_deadline - time.monotonic())
        if timeout <= 0:
            logger.debug(
                "No solve budget left (challenge_type=%s)",
                challenge_type or "unknown",
            )
            return None
        # Absolute deadline for the whole solve, including time spent
        # waiting for the shared solver lock. Navigation and challenge
        # dispatch each clamp to the remaining budget so a single solve
        # can never overshoot the caller's request timeout.
        # Bound lock acquisition: a shared BrowserSolver serializes
        # solves, so without a timeout a concurrent solve could block
        # this caller far past its own timeout. If the lock is busy,
        # skip solving and let the caller report the challenge instead
        # of hanging.
        if not self._lock.acquire(timeout=timeout):
            logger.warning(
                "Browser solve skipped: solver busy (challenge_type=%s waited=%.1fs)",
                challenge_type or "unknown",
                timeout,
            )
            return None
        try:
            # The lock wait may have consumed the whole budget; don't
            # launch a browser we'd have no time to actually use.
            if time.monotonic() >= overall_deadline:
                logger.debug(
                    "Solve budget exhausted waiting for lock (challenge_type=%s)",
                    challenge_type or "unknown",
                )
                return None
            try:
                self._ensure_browser(overall_deadline)
                self._probe_screenxy_patch()
            except Exception as exc:
                logger.warning("Failed to launch browser (%s)", type(exc).__name__)
                return None

            context = None
            try:
                context = self._create_context()
                page = context.new_page()
                self._setup_headless_patches(
                    page,
                    challenge_type=challenge_type,
                )
                size_guard = self._install_navigation_size_limit(
                    page, max_size if embedder is None else None
                )

                if self._browser_ua is None:
                    self._browser_ua = _quiet_read(page, "navigator.userAgent")
                    self._publish_browser_identity()
                    logger.debug("Browser UA: %s", self._browser_ua)

                logger.info(
                    "Browser solving challenge_type=%s",
                    challenge_type or "unknown",
                )

                # Imperva on an API host: navigate the real origin page
                # (earns the registrable-domain reese84/incap cookies) rather
                # than the API URL itself - a top-level nav to an API host is
                # served Imperva's interactive "Error 15" block, which no
                # cookie-poll can pass. The earned cookies replay cross-host
                # (and cross-TLS) to the API host, so the caller's retry over
                # native-TLS / wreq then succeeds. See imperva_embedder.
                if challenge_type == "imperva" and embedder:
                    from wafer.browser._imperva import (
                        imperva_xhr_replay,
                        solve_imperva_embedder,
                    )

                    dispatch_ms = max(
                        1,
                        int((overall_deadline - time.monotonic()) * 1000),
                    )
                    solved = solve_imperva_embedder(self, page, embedder, dispatch_ms)
                    if size_guard["exceeded"]:
                        raise ResponseTooLarge(
                            url,
                            int(size_guard["size"]),
                            max_size,
                        )
                    cookies = context.cookies()
                    if not cookies:
                        logger.warning(
                            "Imperva embedder solve yielded no cookies",
                        )
                        return None

                    # Strongest guarantee: replay the original request as a
                    # same-site XHR from the embedder page (a real-browser
                    # fetch). A 2xx is the exact bytes a browser would get, so
                    # we return it directly; on any failure we fall back to
                    # cookie replay (the harvested token still rides the retry).
                    captured = None
                    if solved and replay:
                        rem_ms = max(
                            1,
                            int((overall_deadline - time.monotonic()) * 1000),
                        )
                        res = imperva_xhr_replay(
                            page,
                            url,
                            replay,
                            rem_ms,
                            max_size=max_size,
                        )
                        # The in-page fetch read the body as text (UTF-8). Only
                        # trust it for text-ish content; a binary body would be
                        # mojibake, so fall back to cookie replay for those.
                        from wafer._base import _is_binary_content_type

                        if (
                            res
                            and 200 <= res["status"] < 300
                            and not _is_binary_content_type(
                                res.get("content_type") or ""
                            )
                        ):
                            body = res["body"].encode("utf-8")
                            if max_size is not None and len(body) > max_size:
                                raise ResponseTooLarge(url, len(body), max_size)
                            captured = CapturedResponse(
                                url=url,
                                status=res["status"],
                                headers={
                                    "content-type": (
                                        res.get("content_type") or "application/json"
                                    )
                                },
                                body=body,
                            )

                    self._last_used = time.monotonic()
                    logger.info(
                        "Imperva embedder solve "
                        "(%d cookies, solved=%s, passthrough=%s)",
                        len(cookies),
                        solved,
                        captured is not None,
                    )
                    return SolveResult(
                        cookies=cookies,
                        user_agent=self._browser_ua or "",
                        extras=None,
                        response=captured,
                        browser_version=self._browser_version,
                    )

                # No JS stealth injection needed.  The launch flag
                # --disable-blink-features=AutomationControlled
                # handles navigator.webdriver natively.  See comment
                # block at top of file for rationale.

                # Kasada: attach /tl listener BEFORE navigation
                # (the /tl POST can fire during page load)
                if challenge_type == "kasada":
                    from wafer.browser._kasada import (
                        setup_kasada_listener,
                    )

                    setup_kasada_listener(page)

                # Keep the response metadata for the document that a TMD solve
                # actually leaves in the main frame. The initial goto response
                # can be the punishment document while a later client-side
                # navigation supplies the real application page.
                tmd_document_responses = []
                if challenge_type == "tmd":

                    def _record_tmd_document(response) -> None:
                        try:
                            request = response.request
                            if request.resource_type != "document":
                                return
                            if request.frame != page.main_frame:
                                return
                        except Exception:
                            return
                        tmd_document_responses.append(response)

                    page.on("response", _record_tmd_document)

                # Snapshot target-scoped TMD clearance before navigation.
                # A punishment page may mint x5sec or automatically redirect
                # during ``goto`` itself; taking the baseline afterward would
                # misclassify that fresh authoritative evidence as pre-existing.
                tmd_retry_target = (
                    _tmd_retry_target(url) if challenge_type == "tmd" else None
                )
                tmd_x5sec_before = (
                    _tmd_x5sec_signatures(context.cookies(), tmd_retry_target)
                    if tmd_retry_target is not None
                    else set()
                )

                # Every main-frame document's (url, status, response), so a
                # post-solve passthrough can return the server's actual body
                # and headers instead of the JS-mutated DOM.
                main_documents: list[tuple[str, int, object]] = []

                def _record_main_document(response) -> None:
                    try:
                        request = response.request
                        if (
                            request.resource_type == "document"
                            and request.frame == page.main_frame
                        ):
                            main_documents.append(
                                (str(response.url), int(response.status), response)
                            )
                    except Exception:
                        return

                page.on("response", _record_main_document)

                # Navigate the origin page when one was supplied
                # (solve_origin / a non-Imperva embedder): the request URL is
                # a JSON/XHR API that can't be top-navigated, so we run the
                # challenge on the real page and let the earned cookies replay
                # to the API host. Falls back to ``url`` for the normal case.
                nav_target = embedder or url
                navigation_response = None
                try:
                    # Bounded, not the whole budget: a WAF interstitial that
                    # never fires domcontentloaded would otherwise consume the
                    # entire solve deadline in navigation and leave nothing for
                    # the solver -- observed as a 295s DataDome "solve" that
                    # never logged a single line. A navigation timeout is
                    # caught below and the solver still runs on what loaded.
                    nav_ms = _navigation_budget_ms(overall_deadline)
                    navigation_response = page.goto(
                        nav_target,
                        wait_until="domcontentloaded",
                        timeout=nav_ms,
                    )
                except Exception as exc:
                    logger.debug(
                        "Browser navigation timeout/error (%s)",
                        type(exc).__name__,
                    )
                self._verify_headless_patches(page)
                if size_guard["exceeded"]:
                    raise ResponseTooLarge(
                        url,
                        int(size_guard["size"]),
                        max_size,
                    )

                # WAF-specific wait strategy — clamp to remaining budget
                dispatch_ms = max(
                    1,
                    int((overall_deadline - time.monotonic()) * 1000),
                )
                dispatch_result = self._dispatch_challenge(
                    page,
                    challenge_type,
                    dispatch_ms,
                    challenge_url=url,
                    documents=main_documents,
                )
                challenge_absent = (
                    challenge_type == "cloudflare"
                    and dispatch_result is None
                )
                solved = dispatch_result is True
                if size_guard["exceeded"]:
                    raise ResponseTooLarge(
                        url,
                        int(size_guard["size"]),
                        max_size,
                    )

                cookies = context.cookies()
                captured = None
                passthrough_without_clearance = False
                passthrough_method = (
                    str(replay.get("method", "GET")).upper()
                    if isinstance(replay, dict)
                    else "GET"
                )

                if challenge_type == "tmd":
                    # Widget/token delivery is only an intermediate event.
                    # A new/changed x5sec is authoritative TRANSPORT clearance.
                    # A challenge-free exact application document is a separate
                    # browser-only outcome: it may be returned for this GET but
                    # cannot be used to claim that wreq replay is unlocked.
                    widget_solved = solved
                    x5sec_ready = False
                    reached_target = False
                    # Bounded on its own, not on the whole solve budget. Poll
                    # both outcomes because a successful navigation can detach
                    # the widget before its handler reports success.
                    clearance_deadline = min(
                        overall_deadline,
                        time.monotonic() + _TMD_CLEARANCE_POLL_SECONDS,
                    )
                    while time.monotonic() < clearance_deadline:
                        if tmd_retry_target is not None:
                            if (
                                _tmd_x5sec_signatures(cookies, tmd_retry_target)
                                - tmd_x5sec_before
                            ):
                                x5sec_ready = True
                                break
                        from wafer.browser._drag import _page_reached_baxia_target

                        try:
                            reached_target = _page_reached_baxia_target(
                                page,
                                url,
                                clearance_deadline,
                            )
                        except Exception:
                            logger.debug(
                                "TMD target-navigation check failed",
                                exc_info=True,
                            )
                        if reached_target:
                            break
                        if not _sleep_before_deadline(clearance_deadline, 0.2):
                            break
                        if tmd_retry_target is not None:
                            cookies = context.cookies()

                    if tmd_retry_target is not None and not x5sec_ready:
                        cookies = context.cookies()
                        x5sec_ready = bool(
                            _tmd_x5sec_signatures(cookies, tmd_retry_target)
                            - tmd_x5sec_before
                        )
                    if os.environ.get("WAFER_TMD_DIAGNOSTICS") == "1":
                        logger.info(
                            "TMD diagnostic: widget_solved=%s "
                            "x5sec_target_new_or_changed=%s "
                            "challenge_free_target=%s "
                            "cookie_structure=%s",
                            widget_solved,
                            x5sec_ready,
                            reached_target,
                            _cookie_structure(cookies),
                        )
                    if (
                        reached_target
                        and not x5sec_ready
                        and nav_target == url
                        and embedder is None
                        and passthrough_method == "GET"
                    ):
                        self._wait_for_hydration(page, overall_deadline)
                        if size_guard["exceeded"]:
                            raise ResponseTooLarge(
                                url,
                                int(size_guard["size"]),
                                max_size,
                            )
                        final_document = (
                            tmd_document_responses[-1]
                            if tmd_document_responses
                            else navigation_response
                        )
                        captured = _capture_tmd_browser_passthrough(
                            final_document,
                            page,
                            url,
                            max_size,
                        )
                        if captured is not None:
                            cookies = context.cookies()
                            passthrough_without_clearance = True
                            logger.info(
                                "TMD reached challenge-free browser content "
                                "without x5sec; returning passthrough (%d bytes)",
                                len(captured.body),
                            )
                    solved = x5sec_ready
                    if not solved and captured is None:
                        logger.warning(
                            "TMD challenge produced neither new target-scoped "
                            "x5sec nor validated browser content "
                            "(widget_solved=%s target_reached=%s)",
                            widget_solved,
                            reached_target,
                        )

                if (
                    captured is None
                    and challenge_absent
                    and nav_target == url
                    and embedder is None
                    and passthrough_method == "GET"
                ):
                    captured = _capture_navigation_passthrough(
                        navigation_response,
                        page,
                        url,
                        max_size,
                    )
                    if captured is not None:
                        logger.info(
                            "Cloudflare absent; returning validated browser "
                            "main document (%d bytes)",
                            len(captured.body),
                        )

                if not cookies and captured is None:
                    logger.warning(
                        "Browser solve yielded no cookies (challenge_type=%s)",
                        challenge_type or "unknown",
                    )
                    return None

                self._last_used = time.monotonic()

                # Post-solve passthrough: after solving, the page
                # may auto-reload to real content.  Capture it
                # when cookie replay is unreliable (TLS-bound).
                # The browser needs time to redirect after cookie
                # update, so retry up to 5s for real content.
                if (
                    solved
                    and challenge_type != "tmd"
                    and captured is None
                    and nav_target == url
                ):
                    # Cap the passthrough wait at the overall deadline so
                    # a near-deadline solve can't overshoot the caller's
                    # request timeout.
                    passthrough_deadline = min(overall_deadline, time.monotonic() + 5)
                    while time.monotonic() < passthrough_deadline:
                        if size_guard["exceeded"]:
                            raise ResponseTooLarge(
                                url,
                                int(size_guard["size"]),
                                max_size,
                            )
                        try:
                            html = self._bounded_page_content(
                                page,
                                max_size,
                            )
                        except Exception:
                            html = ""
                        is_challenge = _is_passthrough_challenge_html(html)
                        # Detect soft-block pages (e.g. F5 Shape
                        # redirects to siteclosed/invitation.html).
                        page_url = page.url.lower()
                        is_block = "invitation" in page_url or "siteclosed" in page_url
                        landed = urlparse(page.url)
                        if _origin_path_identity(landed)[:3] != _origin_path_identity(
                            urlparse(url)
                        )[:3]:
                            # The browser followed a redirect to another
                            # origin. Returning that page would hide the
                            # redirect from follow_redirects=False and from the
                            # caller's per-hop checks, so keep the cookies and
                            # let the replay surface it.
                            logger.info(
                                "%s solve landed on another origin (%s); "
                                "replaying instead of passing the page through",
                                challenge_type or "unknown",
                                landed.hostname,
                            )
                            break
                        landed_status = _main_document_status(main_documents, landed)
                        if landed_status is not None and not 200 <= landed_status < 300:
                            # Not content (a 404, an error page): let the
                            # replay return the server's real status.
                            break
                        if is_cookie_gate(html):
                            # It will not clear by itself; the replay writes
                            # its cookie inline.
                            break
                        if len(html) > 1024 and not is_challenge and not is_block:
                            # Re-read cookies after redirect -
                            # new page may have set more.
                            cookies = context.cookies()
                            # Use the network response body (the bytes the
                            # server sent) instead of the live DOM, which
                            # includes scripts injected at runtime.
                            net_response = _main_document_response(
                                main_documents, landed,
                            )
                            body = None
                            headers: dict[str, str] = {}
                            set_cookie: list[str] = []
                            used_network = False
                            if net_response is not None:
                                try:
                                    body = net_response.body()
                                    if not isinstance(body, bytes):
                                        body = None
                                except Exception:
                                    body = None
                                if body is not None:
                                    headers, set_cookie = _response_headers(
                                        net_response,
                                    )
                                    used_network = True
                            if body is None:
                                body = html.encode("utf-8")
                                headers = {
                                    "content-type": "text/html; charset=utf-8",
                                }
                            captured = CapturedResponse(
                                url=page.url,
                                status=landed_status or 200,
                                headers=headers,
                                body=body,
                                set_cookie=set_cookie,
                            )
                            logger.info(
                                "%s passthrough (%d bytes, %d cookies, "
                                "source=%s)",
                                challenge_type or "unknown",
                                len(body),
                                len(cookies),
                                "network" if used_network else "dom",
                            )
                            break
                        idle(1)

                if solved:
                    logger.info(
                        "Browser solved challenge_type=%s (cookie_count=%d)",
                        challenge_type or "unknown",
                        len(cookies),
                    )
                elif captured is None:
                    logger.warning(
                        "Browser solve did not reach authoritative success "
                        "(challenge_type=%s)",
                        challenge_type or "unknown",
                    )
                    return None

                extras = getattr(page, "_kasada_result", None)

                return SolveResult(
                    cookies=cookies,
                    user_agent=self._browser_ua or "",
                    extras=extras,
                    response=captured,
                    browser_version=self._browser_version,
                    challenge_absent=(
                        passthrough_without_clearance
                        or (challenge_absent and captured is not None)
                    ),
                )

            except ResponseTooLarge:
                raise
            except Exception as exc:
                logger.warning(
                    "Browser solve failed (challenge_type=%s error=%s)",
                    challenge_type or "unknown",
                    type(exc).__name__,
                )
                return None
            finally:
                if context:
                    try:
                        context.close()
                    except Exception:
                        pass
                unbind_page()
        finally:
            self._lock.release()

    # ------------------------------------------------------------------
    # Rendered fetch
    # ------------------------------------------------------------------

    def render(
        self,
        url: str,
        timeout: float | None = None,
        max_size: int | None = None,
        *,
        challenge_budget: float | None = None,
    ) -> SolveResult | None:
        """Navigate ``url`` and return the settled document as a passthrough.

        Unlike :meth:`solve` this requires no cookies and expects no
        challenge: the result is the document after client-side rendering has
        finished, which is the only way to reach content a server ships as an
        empty shell. Redirects are followed by the browser, so the captured
        URL is the final one, and the status and headers describe whichever
        document the body actually came from.

        A page that answers with a WAF interstitial is solved in place using
        the same per-WAF handler :meth:`solve` uses, then re-captured. That
        earns clearance, so the result reports ``challenge_absent=False`` and
        the session pins its replay identity to this browser; a render with no
        challenge reports ``True`` and the session merely merges cookies.

        A non-HTML resource is returned as the bytes the server sent under its
        real content type -Chrome shows JSON, text, XML and images inside a
        generated viewer document, and serializing that would hand back the
        wrapper instead of the resource.

        ``challenge_budget`` (seconds from the call) lets a render that lands
        on a challenge whose solve can outrun ``timeout`` (a reCAPTCHA that
        escalates to image grids) run that long instead; it never shortens
        ``timeout``.
        """

        if threading.get_ident() == self._worker_ident:
            return self._render_on_worker(url, timeout, max_size)
        if not _valid_browser_url(url):
            logger.warning("Refusing invalid browser navigation target")
            return None
        render_timeout = self._solve_timeout if timeout is None else timeout
        if render_timeout <= 0:
            return None
        start = time.monotonic()
        budget = _render_budget(start, render_timeout, challenge_budget)
        future = self._submit_on_worker(
            self._render_on_worker,
            url,
            render_timeout,
            max_size,
            _deadline=budget["deadline"],
            _budget=budget,
        )
        while True:
            # The worker moves the deadline when it lands on a slow challenge.
            remaining = budget["deadline"] - time.monotonic()
            try:
                return future.result(timeout=max(0.0, remaining))
            except FutureTimeoutError:
                # A finished future raised it itself: not a wait to extend.
                if not future.done() and budget["deadline"] > time.monotonic():
                    continue
                break
        cancelled = future.cancel()
        if not cancelled and not future.done():
            self._recover_timed_out_worker(future)
        logger.warning(
            "Browser render timed out after %.1fs",
            time.monotonic() - start,
        )
        return None

    def _render_on_worker(
        self,
        url: str,
        timeout: float | None = None,
        max_size: int | None = None,
        *,
        _deadline: float | None = None,
        _budget: dict | None = None,
    ) -> SolveResult | None:
        """Render ``url`` on the dedicated worker and capture the DOM."""

        if not _valid_browser_url(url):
            logger.warning("Refusing invalid browser navigation target")
            return None
        if timeout is None:
            timeout = self._solve_timeout
        overall_deadline = (
            _deadline if _deadline is not None else time.monotonic() + timeout
        )
        timeout = min(timeout, overall_deadline - time.monotonic())
        if timeout <= 0:
            logger.debug("No render budget left")
            return None
        # Same bounded lock as solve(): a shared solver serializes browser
        # work, and a render must not block its caller past the deadline
        # waiting for someone else's solve to finish.
        if not self._lock.acquire(timeout=timeout):
            logger.warning(
                "Browser render skipped: solver busy (waited=%.1fs)",
                timeout,
            )
            return None
        try:
            if time.monotonic() >= overall_deadline:
                logger.debug("Render budget exhausted waiting for lock")
                return None
            try:
                self._ensure_browser(overall_deadline)
                self._probe_screenxy_patch()
            except Exception as exc:
                logger.warning("Failed to launch browser (%s)", type(exc).__name__)
                return None

            context = None
            try:
                context = self._create_context()
                page = context.new_page()
                self._setup_headless_patches(page, challenge_type=None)
                size_guard = self._install_navigation_size_limit(page, max_size)

                if self._browser_ua is None:
                    self._browser_ua = _quiet_read(page, "navigator.userAgent")
                    self._publish_browser_identity()
                    logger.debug("Browser UA: %s", self._browser_ua)

                logger.info("Browser rendering %s", url)
                # Track main-frame document responses so the status and headers
                # returned describe the SAME document as the captured DOM. A
                # page that client-side redirects after load (location.href)
                # replaces the document, and reporting the first navigation's
                # status against the destination's body would be a lie. A
                # history.pushState route change issues no document response,
                # so the last recorded one stays correct there too.
                document_responses = []

                def _record_document(response) -> None:
                    try:
                        request = response.request
                        if request.resource_type != "document":
                            return
                        if request.frame != page.main_frame:
                            return
                    except Exception:
                        return
                    document_responses.append(response)

                page.on("response", _record_document)
                navigation_response = None
                try:
                    navigation_response = page.goto(
                        url,
                        wait_until="domcontentloaded",
                        timeout=_navigation_budget_ms(overall_deadline),
                    )
                except Exception as exc:
                    logger.debug(
                        "Render navigation timeout/error (%s)",
                        type(exc).__name__,
                    )
                self._verify_headless_patches(page)
                if size_guard["exceeded"]:
                    raise ResponseTooLarge(url, int(size_guard["size"]), max_size)

                self._wait_for_hydration(page, overall_deadline)
                if size_guard["exceeded"]:
                    raise ResponseTooLarge(url, int(size_guard["size"]), max_size)

                html = self._bounded_page_content(page, max_size)
                # A protected page answers the navigation with an interstitial,
                # so the settled DOM is the challenge rather than the content.
                # The browser that would solve it is already on that page: run
                # the same per-WAF handler the solve path uses, then let the
                # page settle again. Returning the interstitial without trying
                # would make render useless on any protected site.
                # Gated on the SAME classifier the session applies to the
                # returned body, not on a narrower structural marker list. The
                # old prefilter knew nothing about TMD, so an Alibaba punish
                # page skipped the solve entirely and was handed back for the
                # session to reject as a challenge -- render could never clear
                # a WAF the transport path clears routinely. Solving in place
                # is a no-op when the classifier finds nothing.
                solved_challenge = False
                if html:
                    # Classified by the status of the document the DOM came
                    # from, as the session will classify the result. Google's
                    # /search answered 200 and then sent the page on to
                    # /sorry/, which answered 429: classified at the goto()
                    # status, its reCAPTCHA was not a challenge, and render
                    # handed it back unsolved (2026-10-06).
                    nav_status = _response_status(
                        _current_document(document_responses, navigation_response)
                    )
                    def extend_for(challenge_value: str) -> float:
                        nonlocal overall_deadline
                        overall_deadline = _extend_render_budget(
                            _budget, challenge_value, overall_deadline
                        )
                        return overall_deadline

                    solved = self._solve_challenge_in_place(
                        page,
                        url,
                        html,
                        overall_deadline,
                        nav_status,
                        extend=extend_for,
                    )
                    if solved:
                        solved_challenge = True
                        from wafer._challenge import detect_challenge

                        # Replay the original navigation with the clearance
                        # state the solve just earned. The solve's own target
                        # navigation can leave a same-URL transition document
                        # in the page; waiting on that document alone was
                        # intermittent, while the transport solve path
                        # reliably retries the original request with the new
                        # cookies. Keep navigation, hydration, and capture
                        # inside one short post-solve budget.
                        # A phase bound, clamped to the caller's deadline. Two
                        # measured failure modes bracket this: at 20s a heavy
                        # page (Alibaba search is ~2.5MB) was captured mid
                        # re-navigation and a working solve was discarded,
                        # while with no bound at all a page that never clears
                        # polled to the caller's timeout and returned no
                        # document, turning an informative ChallengeDetected at
                        # 44s into a ConnectionFailed at 155s. Worst case is
                        # now solve time plus this window.
                        settle_deadline = min(
                            overall_deadline,
                            time.monotonic() + _RENDER_POST_SOLVE_SECONDS,
                        )
                        try:
                            refreshed_response = page.goto(
                                url,
                                wait_until="domcontentloaded",
                                timeout=_navigation_budget_ms(settle_deadline),
                            )
                            if refreshed_response is not None:
                                navigation_response = refreshed_response
                        except Exception as exc:
                            logger.debug(
                                "Post-solve render navigation timeout/error (%s)",
                                type(exc).__name__,
                            )
                        self._wait_for_hydration(page, settle_deadline)
                        while True:
                            if size_guard["exceeded"]:
                                raise ResponseTooLarge(
                                    url,
                                    int(size_guard["size"]),
                                    max_size,
                                )
                            candidate = self._bounded_page_content(page, max_size)
                            if candidate:
                                html = candidate
                                nav_status = _response_status(
                                    _current_document(
                                        document_responses, navigation_response
                                    )
                                )
                                if (
                                    detect_challenge(
                                        nav_status,
                                        {"content-type": "text/html"},
                                        html,
                                        url=url,
                                    )
                                    is None
                                ):
                                    break
                            if not _sleep_before_deadline(settle_deadline, 0.5):
                                break
                if not html and max_size is not None:
                    # _bounded_page_content returns "" for both an absent
                    # document and one over the cap. Ask which it was, so a DOM
                    # that hydrates past the budget raises the same error as an
                    # oversize transfer instead of looking like a failed render.
                    try:
                        rendered_length = _quiet_read(page, _DOCUMENT_LENGTH)
                    except Exception:
                        rendered_length = 0
                    if (
                        isinstance(rendered_length, (int, float))
                        and rendered_length > max_size
                    ):
                        raise ResponseTooLarge(
                            str(page.url) or url,
                            int(rendered_length),
                            max_size,
                        )
                # The document currently in the page, which is the one the DOM
                # above was serialized from. Falls back to the goto() response
                # when the listener recorded nothing (a cached or synthetic
                # document that produced no response event).
                final_response = _current_document(
                    document_responses, navigation_response
                )
                status = _response_status(final_response)
                page_url = str(page.url) or url

                # A non-HTML resource has no DOM worth serializing: Chrome
                # displays JSON, plain text, XML and images inside a generated
                # viewer document, so the "rendered" markup would be that
                # wrapper rather than the resource. Return the bytes the server
                # sent, under their real content type, so resp.json() and
                # resp.content behave as the caller expects.
                served_headers, served_cookies = (
                    _response_headers(final_response)
                    if final_response is not None
                    else ({}, [])
                )
                served_type = (
                    served_headers.get("content-type", "")
                    .split(";")[0]
                    .strip()
                    .lower()
                )
                if served_type and served_type not in _RENDERABLE_CONTENT_TYPES:
                    raw_body = None
                    try:
                        raw_body = final_response.body()
                    except Exception:
                        logger.debug("Could not read non-HTML render body")
                    if isinstance(raw_body, bytes) and raw_body:
                        if max_size is not None and len(raw_body) > max_size:
                            raise ResponseTooLarge(
                                page_url, len(raw_body), max_size
                            )
                        self._last_used = time.monotonic()
                        logger.info(
                            "Rendered %s as %s (%d bytes, not serialized)",
                            page_url,
                            served_type,
                            len(raw_body),
                        )
                        return SolveResult(
                            cookies=context.cookies(),
                            user_agent=self._browser_ua or "",
                            extras=None,
                            response=CapturedResponse(
                                url=page_url,
                                status=status,
                                headers=served_headers,
                                body=raw_body,
                                set_cookie=served_cookies,
                            ),
                            browser_version=self._browser_version,
                            challenge_absent=not solved_challenge,
                        )

                if not html:
                    logger.warning("Render produced no document for %s", url)
                    return None
                body = html.encode("utf-8")
                if max_size is not None and len(body) > max_size:
                    raise ResponseTooLarge(url, len(body), max_size)
                headers, set_cookie = _rendered_headers(final_response)
                cookies = context.cookies()
                self._last_used = time.monotonic()
                logger.info(
                    "Rendered %s (%d bytes, %d cookies)",
                    page_url,
                    len(body),
                    len(cookies),
                )
                # The rendered body is classified by the caller exactly like
                # any other response, so a WAF interstitial that survived the
                # render is reported as a challenge rather than as content.
                return SolveResult(
                    cookies=cookies,
                    user_agent=self._browser_ua or "",
                    extras=None,
                    response=CapturedResponse(
                        url=page_url,
                        status=status,
                        headers=headers,
                        body=body,
                        set_cookie=set_cookie,
                    ),
                    browser_version=self._browser_version,
                    # A plain render earns no clearance identity, so the session
                    # merges its cookies without pinning or rebuilding. A render
                    # that solved a challenge in place DID earn one: its
                    # clearance cookie is bound to the solving browser's UA and
                    # client hints, so the session must pin to that browser or
                    # the first replay is rejected under a mismatched identity.
                    challenge_absent=not solved_challenge,
                )
            except ResponseTooLarge:
                raise
            except Exception as exc:
                logger.warning("Browser render failed (%s)", type(exc).__name__)
                return None
            finally:
                if context:
                    try:
                        context.close()
                    except Exception:
                        pass
                unbind_page()
        finally:
            self._lock.release()

    def _solve_challenge_in_place(
        self,
        page,
        url: str,
        html: str,
        deadline: float,
        status: int = 200,
        extend=None,
    ) -> bool:
        """Run the per-WAF handler on the interstitial a render landed on.

        Classifies with the same detector the session uses, so render and the
        transport path agree on what a body is. Returns whether a solve was
        attempted and reported success - a False leaves the interstitial in
        place for the caller to classify and report as a challenge.
        """

        from wafer._challenge import detect_challenge

        remaining_ms = int((deadline - time.monotonic()) * 1000)
        if remaining_ms <= 0:
            return False
        # The real status first: TMD's punish page is only recognized at 200,
        # so classifying everything as 403 turned every Alibaba slider into a
        # generic JS wait that never ran the drag. Then 403 as a fallback,
        # because other WAFs gate their body markers on a blocking status and
        # would hide from a challenge served in place as 200.
        headers = {"content-type": "text/html"}
        challenge = detect_challenge(status, headers, html, url=url)
        if (
            challenge is None
            and status != 403
            and _is_passthrough_challenge_html(html)
        ):
            challenge = detect_challenge(403, headers, html, url=url)
        if challenge is None:
            return False
        logger.info(
            "Render landed on a %s challenge; solving in place",
            challenge.value,
        )
        if extend is not None:
            deadline = extend(challenge.value)
            remaining_ms = int((deadline - time.monotonic()) * 1000)
        try:
            solved = self._dispatch_challenge(
                page,
                challenge.value,
                remaining_ms,
                challenge_url=url,
            )
        except Exception as exc:
            logger.warning(
                "Render challenge solve failed (challenge_type=%s error=%s)",
                challenge.value,
                type(exc).__name__,
            )
            return False
        # None means "no challenge was present after all" (the Cloudflare
        # handler reports absence that way); re-capturing is right there too.
        return solved is not False

    def _wait_for_hydration(self, page, deadline: float) -> None:
        """Wait for client-side rendering to settle, bounded by ``deadline``.

        Two signals. The network going quiet means client-fetched content (an
        ATS board pulled over XHR) has landed; the serialized DOM holding its
        length across consecutive polls means framework hydration stopped
        mutating it. Neither may have the whole budget: analytics beacons and
        long-polls mean networkidle can never fire on some pages, and a page
        with a running animation never looks stable, so the settle phase is
        capped and both fall through instead of failing.
        """

        settle_deadline = min(deadline, time.monotonic() + _RENDER_SETTLE_CAP)
        idle_ms = int(
            max(0.0, settle_deadline - time.monotonic()) * 1000 * 0.5
        )
        if idle_ms > 0:
            try:
                page.wait_for_load_state("networkidle", timeout=idle_ms)
            except Exception:
                logger.debug(
                    "Render: network did not go idle within %dms",
                    idle_ms,
                )
        previous = -1
        stable = 0
        while stable < _RENDER_STABLE_POLLS and time.monotonic() < settle_deadline:
            try:
                length = _quiet_read(page, _DOCUMENT_LENGTH)
            except Exception:
                return
            if not isinstance(length, (int, float)):
                return
            if length == previous:
                stable += 1
            else:
                stable = 0
                previous = length
            if stable >= _RENDER_STABLE_POLLS:
                return
            if not _sleep_before_deadline(settle_deadline, _RENDER_POLL_INTERVAL):
                return

    def _dispatch_challenge(
        self,
        page,
        challenge_type: str | None,
        timeout_ms: int,
        challenge_url: str | None = None,
        documents: list | None = None,
    ) -> bool | None:
        """Route to the correct WAF-specific solver.

        *documents* is the solve's live list of main-frame ``(url, status)``.
        """
        if challenge_type == "cloudflare":
            from wafer.browser._cloudflare import (
                wait_for_cloudflare,
            )

            return wait_for_cloudflare(self, page, timeout_ms)
        elif challenge_type == "akamai":
            from wafer.browser._akamai import wait_for_akamai

            return wait_for_akamai(self, page, timeout_ms, documents=documents)
        elif challenge_type == "datadome":
            from wafer.browser._datadome import wait_for_datadome

            return wait_for_datadome(self, page, timeout_ms)
        elif challenge_type == "perimeterx":
            from wafer.browser._perimeterx import (
                solve_perimeterx,
            )

            return solve_perimeterx(self, page, timeout_ms)
        elif challenge_type == "awswaf":
            from wafer.browser._awswaf import wait_for_awswaf

            return wait_for_awswaf(self, page, timeout_ms)
        elif challenge_type == "kasada":
            from wafer.browser._kasada import wait_for_kasada

            return wait_for_kasada(self, page, timeout_ms)
        elif challenge_type == "shape":
            from wafer.browser._shape import wait_for_shape

            return wait_for_shape(self, page, timeout_ms)
        elif challenge_type == "imperva":
            from wafer.browser._imperva import wait_for_imperva

            return wait_for_imperva(self, page, timeout_ms)
        elif challenge_type == "geetest":
            from wafer.browser._drag import solve_drag

            return solve_drag(self, page, timeout_ms)
        elif challenge_type == "reddit":
            # The session supplies https://www.reddit.com/ as an embedder.
            # Cookie evidence is authoritative; page load/network-idle is not,
            # because the Shreddit network-security block can look complete.
            return _wait_for_reddit(page, timeout_ms)
        elif challenge_type == "tmd":
            # AliExpress MTop can issue a TMD punishment URL with
            # ``action=captcharecaptcha``.  That is a Google reCAPTCHA flow,
            # not Baxia's slider; forcing it through the slider waits for a
            # widget that never exists and times out.  Dispatch the explicit
            # action solely to the reCAPTCHA solver: a failed reCAPTCHA must
            # be reported, not relabelled as a different challenge type.
            # The top-level navigation can redirect to TMD's child wrapper,
            # whose URL omits the original ``action`` parameter.  Prefer the
            # immutable issued URL supplied to ``solve()`` over the mutable
            # page URL -- but only when that URL is itself a punishment
            # document.  wafer is normally invoked with the *application* URL
            # whose response carried the redirect; that URL never carries an
            # ``action``, so trusting it unconditionally classified every
            # normal-flow reCAPTCHA punishment as a slider and waited for a
            # widget that never exists.
            # A rendered page can also carry the punishment in place: the
            # AliExpress item page shows MTop's reCAPTCHA in a dialog iframe
            # while the main frame stays on the item URL (observed
            # 2026-10-05, ``recom-acs.aliexpress.com``). Without an issued URL
            # to trust, that frame's own ``action`` selects the solver; the
            # slider path waited out the whole render budget instead.
            from wafer._base import (
                _tmd_is_punish_url,
                _tmd_is_recaptcha_challenge,
            )

            issued_url = challenge_url if _tmd_is_punish_url(challenge_url) else None
            action_url = issued_url or page.url or challenge_url or ""

            if _tmd_is_recaptcha_challenge(action_url) or (
                issued_url is None and _tmd_recaptcha_frame_present(page)
            ):
                from wafer.browser._recaptcha import wait_for_recaptcha

                return wait_for_recaptcha(
                    self,
                    page,
                    timeout_ms,
                    protocol_completion_is_intermediate=True,
                )
            from wafer.browser._drag import solve_baxia

            return solve_baxia(self, page, timeout_ms, challenge_url=challenge_url)
        elif challenge_type == "baxia":
            from wafer.browser._drag import solve_baxia

            return solve_baxia(self, page, timeout_ms, challenge_url=challenge_url)
        elif challenge_type == "hcaptcha":
            from wafer.browser._hcaptcha import wait_for_hcaptcha

            return wait_for_hcaptcha(self, page, timeout_ms)
        elif challenge_type == "recaptcha":
            from wafer.browser._recaptcha import wait_for_recaptcha

            return wait_for_recaptcha(self, page, timeout_ms)
        else:
            return self._wait_for_generic(page, timeout_ms)

    def _wait_for_generic(self, page, timeout_ms: int) -> bool:
        """Generic wait: bounded quiescence + extra time for JS execution."""
        deadline = time.monotonic() + max(timeout_ms, 0) / 1000
        try:
            # "networkidle" must never be given the whole budget. Analytics
            # beacons, websockets and long-polls mean it can never fire, and
            # when it consumed everything the settle below was skipped and the
            # solve reported failure on a page that had already cleared. Cap
            # it at half the budget and always fall through: the settle is
            # what actually lets the challenge JS finish.
            idle_ms = int(max(0.0, deadline - time.monotonic()) * 1000 * 0.5)
            if idle_ms > 0:
                try:
                    page.wait_for_load_state("networkidle", timeout=idle_ms)
                except Exception:
                    logger.debug(
                        "Generic wait: network did not go idle within %dms",
                        idle_ms,
                    )
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            idle(min(2.0, remaining))
            return time.monotonic() <= deadline
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Iframe interception
    # ------------------------------------------------------------------

    def intercept_iframe(
        self,
        embedder_url: str,
        target_domain: str,
        timeout: float | None = None,
    ) -> InterceptResult | None:
        """Intercept iframe traffic within one end-to-end deadline."""

        if not _valid_browser_url(embedder_url):
            logger.warning("Refusing invalid iframe embedder navigation target")
            return None
        target_domain = target_domain.lstrip(".").rstrip(".").lower()
        if (
            not target_domain
            or "/" in target_domain
            or "\\" in target_domain
            or any(char.isspace() for char in target_domain)
        ):
            logger.warning("Refusing invalid iframe target domain")
            return None
        if threading.get_ident() == self._worker_ident:
            return self._intercept_iframe_on_worker(
                embedder_url,
                target_domain,
                timeout,
            )
        intercept_timeout = self._solve_timeout if timeout is None else timeout
        if intercept_timeout <= 0:
            return None
        deadline = time.monotonic() + intercept_timeout
        future = self._submit_on_worker(
            self._intercept_iframe_on_worker,
            embedder_url,
            target_domain,
            intercept_timeout,
            _deadline=deadline,
        )
        try:
            return future.result(timeout=intercept_timeout)
        except FutureTimeoutError:
            # cancel() cannot stop an already-running task, and after a full
            # intercept_timeout it is always running. Without recovery the
            # stalled operation keeps the *serial* worker forever and every
            # later solve on this solver blocks. Mirror solve()'s handling.
            cancelled = future.cancel()
            if not cancelled and not future.done():
                self._recover_timed_out_worker(future)
            logger.warning(
                "Iframe intercept timed out after %.1fs "
                "(target_domain=%s worker_continues=%s)",
                intercept_timeout,
                target_domain,
                not cancelled and not future.done(),
            )
            return None

    def _intercept_iframe_on_worker(
        self,
        embedder_url: str,
        target_domain: str,
        timeout: float | None = None,
        *,
        _deadline: float | None = None,
    ) -> InterceptResult | None:
        """Navigate to an embedder page and capture iframe traffic.

        Loads ``embedder_url`` in a real browser, waits for iframes to
        load, and captures all HTTP responses + cookies from
        ``target_domain``.

        Args:
            embedder_url: The page containing the iframe to intercept.
            target_domain: Domain to capture traffic from. Matches any
                subdomain (e.g., "marinetraffic.com" matches
                "www.marinetraffic.com").
            timeout: Max seconds to wait. Defaults to ``solve_timeout``.

        Returns:
            InterceptResult with cookies and captured responses, or
            None on failure.
        """
        if not _valid_browser_url(embedder_url):
            logger.warning("Refusing invalid iframe embedder navigation target")
            return None
        if timeout is None:
            timeout = self._solve_timeout
        overall_deadline = (
            _deadline if _deadline is not None else time.monotonic() + timeout
        )
        timeout = min(timeout, overall_deadline - time.monotonic())
        if timeout <= 0:
            return None

        # Bound lock acquisition so a concurrent solve() on the shared
        # solver can't block this intercept past its own timeout.
        if not self._lock.acquire(timeout=max(timeout, 0.0)):
            logger.warning(
                "Iframe intercept skipped: solver busy (target_domain=%s waited=%.1fs)",
                target_domain,
                timeout,
            )
            return None
        try:
            try:
                self._ensure_browser(overall_deadline)
                self._probe_screenxy_patch()
            except Exception as exc:
                logger.warning(
                    "Failed to launch browser for iframe intercept (%s)",
                    type(exc).__name__,
                )
                return None

            context = None
            try:
                context = self._create_context()
                page = context.new_page()
                self._setup_headless_patches(page)

                if self._browser_ua is None:
                    self._browser_ua = _quiet_read(page, "navigator.userAgent")
                    self._publish_browser_identity()

                captured: list[CapturedResponse] = []

                def _on_response(response):
                    try:
                        url = response.url
                        # Match target domain (including subdomains)
                        from urllib.parse import urlparse

                        host = urlparse(url).hostname or ""
                        if not (
                            host == target_domain or host.endswith("." + target_domain)
                        ):
                            return
                        # Read body — may fail for redirects/empty
                        try:
                            body = response.body()
                        except Exception:
                            body = b""
                        headers = {}
                        try:
                            for k, v in response.headers.items():
                                headers[k] = v
                        except Exception:
                            pass
                        captured.append(
                            CapturedResponse(
                                url=url,
                                status=response.status,
                                headers=headers,
                                body=body,
                            )
                        )
                    except Exception:
                        pass

                page.on("response", _on_response)

                logger.info(
                    "Iframe intercept: capturing target_domain=%s",
                    target_domain,
                )

                try:
                    # Bounded for the same reason as the solve navigation: a
                    # stalled embedder must not eat the budget the iframe
                    # capture and cookie read still need.
                    page.goto(
                        embedder_url,
                        wait_until="domcontentloaded",
                        timeout=_navigation_budget_ms(overall_deadline),
                    )
                except Exception as exc:
                    logger.debug(
                        "Iframe intercept navigation timeout/error (%s)",
                        type(exc).__name__,
                    )

                # Wait for network to settle (iframes loading). Bounded to
                # half the remaining budget: an embedder page that keeps a
                # connection open never reaches "networkidle", and spending
                # everything here left nothing for the settle and cookie read
                # below, so the intercept returned None on a page that had
                # loaded fine.
                remaining_ms = int(
                    max(0.0, overall_deadline - time.monotonic()) * 1000 * 0.5
                )
                if remaining_ms > 0:
                    try:
                        page.wait_for_load_state("networkidle", timeout=remaining_ms)
                    except Exception:
                        logger.debug(
                            "Iframe intercept: network did not go idle within %dms",
                            remaining_ms,
                        )

                # Brief extra settle for late JS
                remaining = overall_deadline - time.monotonic()
                if remaining <= 0:
                    return None
                idle(min(1.0, remaining))
                if time.monotonic() > overall_deadline:
                    return None

                # Extract cookies for target domain
                all_cookies = context.cookies()
                target_cookies = [
                    c
                    for c in all_cookies
                    if (
                        c.get("domain", "").lstrip(".").rstrip(".").lower()
                        == target_domain
                        or c.get("domain", "")
                        .rstrip(".")
                        .lower()
                        .endswith("." + target_domain)
                    )
                ]

                self._last_used = time.monotonic()

                logger.info(
                    "Iframe intercept captured %d responses, %d cookies from %s",
                    len(captured),
                    len(target_cookies),
                    target_domain,
                )

                return InterceptResult(
                    cookies=target_cookies,
                    responses=captured,
                    user_agent=self._browser_ua or "",
                )

            except Exception as exc:
                logger.warning(
                    "Iframe intercept failed (target_domain=%s error=%s)",
                    target_domain,
                    type(exc).__name__,
                )
                return None
            finally:
                if context:
                    try:
                        context.close()
                    except Exception:
                        pass
                unbind_page()
        finally:
            self._lock.release()

    async def asolve(
        self,
        url: str,
        challenge_type: str | None = None,
        timeout: float | None = None,
        embedder: str | None = None,
        replay: dict | None = None,
        max_size: int | None = None,
    ) -> "SolveResult | None":
        """Async wrapper around :meth:`solve` - identical args and result.

        ``solve`` drives Playwright's blocking API under a lock, so it would
        stall an event loop if awaited directly. This dispatches it to a
        thread executor and awaits it, letting an async app drive the solver
        manually (``await solver.asolve(url)``) without blocking the loop.
        Pure dispatch - all solve logic lives in :meth:`solve`.
        """
        solve_timeout = self._solve_timeout if timeout is None else timeout
        if solve_timeout <= 0:
            return None
        deadline = time.monotonic() + solve_timeout
        solve_callable = self.solve
        base_solve = (
            getattr(solve_callable, "__func__", None) is BrowserSolver.solve
        )

        def invoke_solve():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            if base_solve:
                return self._solve_on_worker(
                    url,
                    challenge_type,
                    solve_timeout,
                    embedder,
                    replay,
                    max_size,
                    _deadline=deadline,
                )
            args = (url, challenge_type, solve_timeout, embedder, replay)
            from wafer._base import _callable_accepts_keyword

            if max_size is None or not _callable_accepts_keyword(
                solve_callable,
                "max_size",
            ):
                return solve_callable(*args)
            return solve_callable(*args, max_size=max_size)

        future = self._submit_on_worker(invoke_solve)
        try:
            return await asyncio.wait_for(
                asyncio.wrap_future(future),
                timeout=solve_timeout,
            )
        except asyncio.CancelledError:
            cancelled = future.cancel()
            if not cancelled and not future.done():
                self._recover_timed_out_worker(future)
            logger.warning(
                "Browser solve caller cancelled "
                "(challenge_type=%s worker_continues=%s)",
                challenge_type or "unknown",
                not cancelled and not future.done(),
            )
            raise
        except TimeoutError:
            if time.monotonic() < deadline:
                raise
            cancelled = future.cancel()
            if not cancelled and not future.done():
                self._recover_timed_out_worker(future)
            logger.warning(
                "Browser solve timed out after %.1fs "
                "(challenge_type=%s worker_continues=%s)",
                solve_timeout,
                challenge_type or "unknown",
                not cancelled and not future.done(),
            )
            return None

    async def arender(
        self,
        url: str,
        timeout: float | None = None,
        max_size: int | None = None,
        *,
        challenge_budget: float | None = None,
    ) -> "SolveResult | None":
        """Async wrapper around :meth:`render` - identical args and result.

        Pure dispatch onto the solver's worker, mirroring :meth:`asolve`:
        the render drives Playwright's blocking API, so awaiting it directly
        would stall the event loop.
        """
        render_timeout = self._solve_timeout if timeout is None else timeout
        if render_timeout <= 0:
            return None
        start = time.monotonic()
        budget = _render_budget(start, render_timeout, challenge_budget)
        deadline = budget["deadline"]
        render_callable = self.render
        base_render = (
            getattr(render_callable, "__func__", None) is BrowserSolver.render
        )

        def invoke_render():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            if base_render:
                return self._render_on_worker(
                    url,
                    render_timeout,
                    max_size,
                    _deadline=deadline,
                    _budget=budget,
                )
            from wafer._base import _callable_accepts_keyword

            if max_size is None or not _callable_accepts_keyword(
                render_callable,
                "max_size",
            ):
                return render_callable(url, render_timeout)
            return render_callable(url, render_timeout, max_size=max_size)

        future = self._submit_on_worker(invoke_render)
        wrapped = asyncio.wrap_future(future)
        try:
            while True:
                # The worker moves the deadline when it lands on a slow
                # challenge; shield the future so waiting again keeps it.
                remaining = budget["deadline"] - time.monotonic()
                try:
                    return await asyncio.wait_for(
                        asyncio.shield(wrapped), timeout=max(0.0, remaining)
                    )
                except TimeoutError:
                    if wrapped.done():
                        raise  # the render's own error, not this wait's
                    if budget["deadline"] > time.monotonic():
                        continue
                    raise
        except asyncio.CancelledError:
            cancelled = future.cancel()
            if not cancelled and not future.done():
                self._recover_timed_out_worker(future)
            logger.warning(
                "Browser render caller cancelled (worker_continues=%s)",
                not cancelled and not future.done(),
            )
            raise
        except TimeoutError:
            if wrapped.done() and time.monotonic() < budget["deadline"]:
                raise
            cancelled = future.cancel()
            if not cancelled and not future.done():
                self._recover_timed_out_worker(future)
            logger.warning(
                "Browser render timed out after %.1fs (worker_continues=%s)",
                time.monotonic() - start,
                not cancelled and not future.done(),
            )
            return None

    async def aintercept_iframe(
        self,
        embedder_url: str,
        target_domain: str,
        timeout: float | None = None,
    ) -> "InterceptResult | None":
        """Async wrapper around :meth:`intercept_iframe` - same args/result.

        Dispatches the blocking interception to a thread executor so it can
        be awaited from an event loop without blocking it. Pure dispatch.
        """
        intercept_timeout = self._solve_timeout if timeout is None else timeout
        if intercept_timeout <= 0:
            return None
        deadline = time.monotonic() + intercept_timeout
        intercept_callable = self.intercept_iframe
        base_intercept = (
            getattr(intercept_callable, "__func__", None)
            is BrowserSolver.intercept_iframe
        )

        def invoke_intercept():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            if base_intercept:
                return self._intercept_iframe_on_worker(
                    embedder_url,
                    target_domain,
                    intercept_timeout,
                    _deadline=deadline,
                )
            return intercept_callable(
                embedder_url,
                target_domain,
                intercept_timeout,
            )

        future = self._submit_on_worker(invoke_intercept)
        try:
            return await asyncio.wait_for(
                asyncio.wrap_future(future),
                timeout=intercept_timeout,
            )
        except asyncio.CancelledError:
            # Caller cancellation (a request deadline firing, an enclosing
            # wait_for) leaves the submitted operation running on the serial
            # worker. asolve() recovers here; without the same handling an
            # intercept wedges every later solve on this solver.
            cancelled = future.cancel()
            if not cancelled and not future.done():
                self._recover_timed_out_worker(future)
            logger.warning(
                "Iframe intercept caller cancelled "
                "(target_domain=%s worker_continues=%s)",
                target_domain,
                not cancelled and not future.done(),
            )
            raise
        except TimeoutError:
            if time.monotonic() < deadline:
                raise
            cancelled = future.cancel()
            if not cancelled and not future.done():
                self._recover_timed_out_worker(future)
            logger.warning(
                "Iframe intercept timed out after %.1fs (target_domain=%s)",
                intercept_timeout,
                target_domain,
            )
            return None

    def close(self, timeout: float | None = None) -> bool:
        """Shut down the browser on its owning thread.

        ``timeout`` bounds waiting when the worker is busy with a challenge.
        In that case the queued close remains ordered behind the active task,
        but the caller can continue its shutdown without waiting for an
        uninterruptible browser operation.  The default preserves the prior
        synchronous-close behavior for library callers.

        Returns ``True`` when the close completed before the timeout.
        """
        if timeout is not None and timeout < 0:
            raise ValueError("timeout must be non-negative or None")
        if threading.get_ident() == self._worker_ident:
            with self._executor_lock:
                if self._executor_closed:
                    return bool(self._close_future is None or self._close_future.done())
                self._executor_closed = True
            self._close_on_worker()
            self._executor.shutdown(wait=False)
            return True
        with self._executor_lock:
            future = self._close_future
            if future is None:
                if self._executor_closed:
                    return True
                future = self._executor.submit(self._close_on_worker)
                self._close_future = future
                self._executor_closed = True
        try:
            future.result(timeout=timeout)
        except FutureTimeoutError:
            # Do not cancel the close: it must run after the task which owns
            # the browser.  ``wait=False`` makes this a bounded caller wait;
            # Python will release the worker after that ordered close runs.
            self._executor.shutdown(wait=False)
            logger.warning(
                "BrowserSolver close exceeded %.1fs; continuing shutdown",
                timeout,
            )
            return False
        self._executor.shutdown(wait=True)
        return True

    def _close_on_worker(self) -> None:
        self._worker_ident = threading.get_ident()
        try:
            with self._lock:
                self._close_browser()
                logger.debug("BrowserSolver closed")
        finally:
            # Never let a recycled OS thread ID be mistaken for this closed
            # solver's owning worker.
            self._worker_ident = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
