"""AsyncSession -- async HTTP client wrapping wreq.Client."""

import asyncio
import datetime
import logging
import time

import wreq
import wreq.exceptions
from wreq import Method

from wafer._base import (
    BaseSession,
    _aread_body_capped,
    _CapExceeded,
    _content_length_over_cap,
    _decode_headers,
    _extract_location,
    _is_binary_content_type,
    _is_challengeable_content_type,
    _to_method,
)
from wafer._challenge import (
    JS_ONLY_CHALLENGES,
    ChallengeType,
    detect_challenge,
)
from wafer._cookies import (
    cookie_domain_matches,
    extract_domain,
    registrable_domain,
)
from wafer._errors import (
    ChallengeDetected,
    ConnectionFailed,
    EmptyResponse,
    RateLimited,
    ResponseTooLarge,
    TooManyRedirects,
    WaferTimeout,
)
from wafer._fingerprint import chrome_version_from_ua, emulation_for_version
from wafer._native_tls import NATIVE_MAX_RETRIES
from wafer._profiles import Profile
from wafer._response import HistoryEntry, WaferResponse, resolve_charset
from wafer._retry import RetryState, calculate_backoff, parse_retry_after
from wafer._solvers import (
    parse_amazon_captcha,
    solve_acw,
    tmd_homepage_url,
)

logger = logging.getLogger("wafer")


class AsyncSession(BaseSession):
    """Asynchronous HTTP session with anti-detection defaults."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if self._profile is Profile.OPERA_MINI:
            self._client = None  # Opera Mini bypasses wreq entirely
        else:
            self._client = wreq.Client(**self._build_client_kwargs())
            self._hydrate_jar_from_cache()
        self._rotate_lock = asyncio.Lock()

    def _hydrate_jar_from_cache(self) -> None:
        """Load cached cookies from disk into the client's jar."""
        if self._cookie_cache is None:
            return
        try:
            for domain in self._cookie_cache.list_domains():
                cookies = self._cookie_cache.load(domain)
                for cookie in cookies:
                    try:
                        self._client.cookie_jar.add(
                            cookie["raw"], cookie["url"]
                        )
                    except Exception as e:
                        logger.debug(
                            "Failed to hydrate cookie %s: %s",
                            cookie.get("name", "?"),
                            e,
                        )
        except Exception:
            logger.debug(
                "Failed to hydrate cookies from cache",
                exc_info=True,
            )

    async def _cache_response_cookies(self, url: str, resp) -> None:
        """Write-through: save Set-Cookie headers to disk cache."""
        if self._cookie_cache is None:
            return
        try:
            domain = extract_domain(url)
            if not domain:
                return
            raw_cookies = resp.headers.get_all("set-cookie")
            if raw_cookies:
                await asyncio.to_thread(
                    self._cookie_cache.save_from_headers,
                    domain,
                    raw_cookies,
                    url,
                )
        except Exception:
            logger.debug(
                "Failed to cache cookies for %s",
                url,
                exc_info=True,
            )

    def _rebuild_client(self) -> None:
        """Rebuild the wreq client with a fresh TLS session and cookie jar.

        Creates a new wreq.Client, discarding the old client's connection
        pool, TLS session tickets, and in-memory cookie jar. Only cookies
        persisted to disk cache (via _cache_response_cookies or browser
        solve) survive the rebuild; normal HTTP response cookies that were
        only in the in-memory jar are intentionally lost.

        This is correct for rotation/retirement: cookies are bound to the
        TLS fingerprint that earned them, and replaying them on a different
        fingerprint can trigger WAF flags. For rotate_every (unlinkable
        request sequences), cookie loss is the desired isolation property.
        """
        self._client = wreq.Client(**self._build_client_kwargs())
        self._hydrate_jar_from_cache()
        logger.debug(
            "Client rebuilt with emulation=%s", self.emulation
        )

    async def _retire_session(self, domain: str) -> None:
        """Full identity reset: new fingerprint, empty jar, clear cache."""
        # Restore Chrome if rotated to Safari (not explicit Safari profile)
        if (
            self._safari_identity is not None
            and self._profile is not Profile.SAFARI
        ):
            self._switch_to_chrome()
        if self._fingerprint is not None:
            self._fingerprint.reset()
        if self._cookie_cache:
            await asyncio.to_thread(
                self._cookie_cache.clear, domain
            )
        self._client = wreq.Client(**self._build_client_kwargs())
        self._hydrate_jar_from_cache()
        self._domain_failures.pop(domain, None)
        logger.warning(
            "Session retired for %s: emulation=%s",
            domain,
            self.emulation,
        )

    async def _try_inline_solve(
        self, challenge: ChallengeType | None, body: str, url: str
    ) -> bool:
        """Attempt inline challenge solving. Returns True if solved."""
        if challenge == ChallengeType.ACW:
            cookie_value = solve_acw(body)
            if cookie_value:
                cookie_str = f"acw_sc__v2={cookie_value}; Path=/"
                self._client.cookie_jar.add(cookie_str, url)
                # Persist to disk cache
                if self._cookie_cache:
                    domain = extract_domain(url)
                    if domain:
                        await asyncio.to_thread(
                            self._cookie_cache.save,
                            domain,
                            [
                                {
                                    "name": "acw_sc__v2",
                                    "raw": cookie_str,
                                    "url": url,
                                    "expires": 0,
                                    "last_used": time.time(),
                                }
                            ],
                        )
                logger.info("ACW challenge solved inline")
                return True

        elif challenge == ChallengeType.AMAZON:
            target = parse_amazon_captcha(body, url)
            if target:
                try:
                    if target["method"] == "POST":
                        solve_resp = await self._client.post(
                            target["url"],
                            form=target["params"],
                            headers={"Referer": url},
                        )
                    else:
                        solve_resp = await self._client.get(
                            target["url"],
                            params=target["params"] or None,
                            headers={"Referer": url},
                        )
                    await self._cache_response_cookies(
                        target["url"], solve_resp
                    )
                    logger.info(
                        "Amazon captcha submitted inline to %s",
                        target["url"],
                    )
                    return True
                except Exception:
                    logger.debug(
                        "Amazon inline solve failed", exc_info=True
                    )

        elif challenge == ChallengeType.TMD:
            homepage = tmd_homepage_url(url)
            try:
                homepage_resp = await self._client.get(homepage)
                await self._cache_response_cookies(
                    homepage, homepage_resp
                )
                logger.info("TMD session warmed via %s", homepage)
                return True
            except Exception:
                logger.debug(
                    "TMD homepage fetch failed", exc_info=True
                )

        return False

    async def _try_browser_solve(
        self,
        challenge: ChallengeType,
        url: str,
        deadline: float | None = None,
        embedder: str | None = None,
        replay: dict | None = None,
        max_size: int | None = None,
    ) -> WaferResponse | bool:
        """Attempt browser-based challenge solving.

        Args:
            deadline: monotonic-clock deadline for the overall request.
                When set (a per-request ``timeout=`` was passed), the
                browser solve is clamped to the remaining budget so it
                can't block the caller past their timeout. ``None`` means
                use the solver's own ``solve_timeout`` default.
            embedder: a same-site origin page to navigate/solve on instead
                of the API ``url``. Fed by the session-level ``solve_origin``
                (any challenge type) or the Imperva heuristic embedder
                (``imperva_embedder``). For a generic embedder no passthrough
                body is returned - the earned cookies come back so the session
                retries the real ``url``.
            replay: Imperva embedder only - ``{method, body, content_type}``
                replayed as a same-site XHR for a passthrough response.
            max_size: effective ``max_response_size`` (bytes). When a
                passthrough body exceeds it, ``ResponseTooLarge`` is raised
                instead of returning the oversize body.

        Returns:
            WaferResponse: browser got real content without challenge
                (passthrough - caller should return this directly).
            True: challenge solved, cookies injected - caller should
                retry the TLS request.
            False: browser solve failed (or no time budget remained).
        """
        from wafer.browser import format_cookie_str

        solve_timeout: float | None = None
        if deadline is not None:
            solve_timeout = deadline - time.monotonic()
            if solve_timeout <= 0:
                logger.debug(
                    "No time budget left for browser solve at %s", url
                )
                return False

        # solve_origin generalizes the Imperva embedder to every challenge:
        # navigate the browser to the caller-supplied origin page (where the
        # WAF token is mintable) instead of the API ``url`` (raw JSON would
        # never run the challenge JS). For Imperva it overrides the auto-derived
        # embedder; for all other challenge types it is passed as the embedder
        # so the solver navigates it, runs the challenge there, then the
        # registrable-domain cookies replay to the API session on retry. The
        # original ``url`` is still used below for cookie-domain filtering and
        # caching so the token lands on the API host's registrable domain.
        if self._solve_origin:
            embedder = self._solve_origin
        result = await asyncio.to_thread(
            self._browser_solver.solve,
            url,
            challenge.value,
            timeout=solve_timeout,
            embedder=embedder,
            replay=replay,
        )
        if result is None:
            return False

        domain = extract_domain(url) or ""

        # Filter cookies to the target's registrable domain (browser context
        # returns cookies for all domains including CDN/challenge subdomains
        # like challenges.cloudflare.com). Match on the registrable domain, not
        # the exact host: an Imperva embedder solve earns the WAF token on
        # ``.realtor.ca`` while the request URL is ``api2.realtor.ca``, so a
        # host-exact match would drop ``reese84``.
        reg = registrable_domain(domain)
        target_cookies = [
            c for c in result.cookies
            if cookie_domain_matches(c.get("domain", ""), reg)
        ] or result.cookies  # fallback to all if filter matches none

        # Persist browser cookies to disk cache
        if self._cookie_cache and domain:
            cache_entries = []
            for cookie in target_cookies:
                raw = format_cookie_str(cookie)
                expires = cookie.get("expires", -1)
                cache_entries.append(
                    {
                        "name": cookie["name"],
                        "raw": raw,
                        "url": url,
                        "expires": (
                            time.time() + 86400
                            if expires <= 0
                            else float(expires)
                        ),
                        "last_used": time.time(),
                    }
                )
            await asyncio.to_thread(
                self._cookie_cache.save, domain, cache_entries
            )

        # Cache Kasada CT/ST tokens for per-request CD generation
        if result.extras and "ct" in result.extras:
            from wafer._kasada import store_session
            store_session(
                domain,
                ct=result.extras["ct"],
                st=result.extras.get("st", 0),
                cookies=target_cookies,
            )

        # Match emulation to browser's Chrome version and pin it.
        # Cookies are TLS-bound — rotation away from the matched
        # fingerprint would invalidate them.
        # Skip for Safari — keep Safari TLS identity after browser solve.
        if self._fingerprint is not None:
            chrome_ver = chrome_version_from_ua(result.user_agent)
            if chrome_ver:
                em = emulation_for_version(chrome_ver)
                if em:
                    self._fingerprint.reset(em)
                    self._fingerprint.pin()

        # Rebuild client (rehydrates cookies from cache)
        self._rebuild_client()

        # Also inject directly into jar (covers cache-disabled case)
        for cookie in target_cookies:
            try:
                self._client.cookie_jar.add(
                    format_cookie_str(cookie), url
                )
            except Exception as e:
                logger.debug(
                    "Failed to inject cookie %s: %s",
                    cookie.get("name", "?"),
                    e,
                )

        # Imperva: the earned reese84/incap token replays over OpenSSL, so
        # seed the native jar - a later native-TLS probe (e.g. after load
        # eases) then carries the token. We deliberately do NOT pin native
        # here: the browser solve only fires under rate escalation, where the
        # OpenSSL free pass is revoked and native+token is itself challenged,
        # while wreq carries the token fine (the documented heavy-state path).
        # The immediate retry is left unpinned so it rides wreq; the existing
        # per-request native probe re-pins later if/when the free pass returns.
        if challenge == ChallengeType.IMPERVA and self._native_tls_usable():
            try:
                self._native_transport().add_cookies(target_cookies)
            except Exception as e:
                logger.debug("Failed to seed native-TLS jar: %s", e)

        # Passthrough: browser got real content without solving
        if result.response is not None:
            body_bytes = result.response.body
            # Enforce the response-size cap on the browser body too (it never
            # went through the wreq capped-read path).
            if max_size is not None and len(body_bytes) > max_size:
                raise ResponseTooLarge(
                    result.response.url, len(body_bytes), max_size
                )
            logger.info(
                "Browser passthrough %s at %s "
                "(%d cookies injected, %d bytes)",
                challenge.value,
                url,
                len(target_cookies),
                len(body_bytes),
            )
            text = body_bytes.decode("utf-8", errors="replace")
            return WaferResponse(
                status_code=result.response.status,
                headers=result.response.headers,
                url=result.response.url,
                content=body_bytes,
                text=text,
                was_retried=True,
                emulation=self._serving_emulation_repr(),
                # Individual Set-Cookie values from the captured response
                # (the flat headers dict joins multi-value headers with
                # "; ", which is lossy for Set-Cookie). Mirrors native-TLS.
                raw_set_cookie=getattr(
                    result.response, "set_cookie", None
                ) or None,
            )

        logger.info(
            "Browser solved %s at %s (%d cookies injected)",
            challenge.value,
            url,
            len(target_cookies),
        )
        return True

    async def _try_native_tls(
        self,
        method: str,
        url: str,
        extra_headers: dict[str, str] | None,
        kwargs: dict,
        deadline: float | None,
        start_time: float,
        state,
        max_size: int | None = None,
    ) -> WaferResponse | None:
        """Replay a request over system OpenSSL (urllib), off the wreq path.

        Returns a WaferResponse for any HTTP reply (its ``challenge_type``
        is set if the bypass itself got challenged), or None on a transport
        error or exhausted time budget. ``max_size`` (the effective
        ``max_response_size``) bounds the native body read + decompression.
        """
        timeout = self.timeout.total_seconds()
        if deadline is not None:
            timeout = deadline - time.monotonic()
            if timeout <= 0:
                return None
        headers, body = self._native_prepare(extra_headers, kwargs)
        transport = self._native_transport()
        try:
            # *rest keeps older 4-tuple transports (test fakes) working;
            # the real transport returns the Set-Cookie list as 5th item.
            status, hdrs, body_bytes, final_url, *rest = (
                await asyncio.to_thread(
                    transport.request,
                    method, url, headers, body, timeout, max_size,
                )
            )
        except (ResponseTooLarge, TooManyRedirects):
            # Hard limits (size cap, redirect loop), not transport hiccups:
            # propagate rather than swallowing into a None (which would fall
            # back to the wreq path and silently bypass the limit).
            raise
        except Exception:
            logger.warning(
                "Native-TLS request failed for %s", url, exc_info=True
            )
            return None
        return self._native_make_response(
            status, hdrs, body_bytes, final_url, start_time, state,
            raw_set_cookie=rest[0] if rest else None,
        )

    def _make_response(
        self,
        *,
        status_code: int,
        headers: dict[str, str],
        url: str,
        start_time: float,
        was_retried: bool,
        content: bytes | None = None,
        text: str | None = None,
        challenge_type: str | None = None,
        state: RetryState | None = None,
        history: list | None = None,
        raw=None,
    ) -> WaferResponse:
        if content is None and text is not None:
            content = text.encode("utf-8")
        return WaferResponse(
            status_code=status_code,
            content=content or b"",
            text=text,
            headers=headers,
            url=url,
            history=history,
            elapsed=time.monotonic() - start_time,
            was_retried=was_retried,
            retries=state.normal_retries if state else 0,
            rotations=state.rotation_retries if state else 0,
            inline_solves=state.inline_solves if state else 0,
            challenge_type=challenge_type,
            emulation=self._serving_emulation_repr(),
            raw=raw,
        )

    async def request(
        self, method: str, url: str, **kwargs
    ) -> WaferResponse:
        """Send an HTTP request with retry, backoff, and challenge handling."""
        start_time = time.monotonic()

        # Extract per-request overrides (popped once, reused)
        extra_headers = kwargs.pop("headers", None)
        params = kwargs.pop("params", None)
        req_timeout = kwargs.pop("timeout", None)
        req_attempt_timeout = kwargs.pop("attempt_timeout", None)
        # Per-request response-size cap overrides the session value.
        max_response_size = kwargs.pop(
            "max_response_size", self.max_response_size
        )
        if params:
            url = self._apply_params(url, params)

        # `timeout=` is the TOTAL budget for the whole call - every retry,
        # rotation, and browser solve - whether it is passed per-request or
        # taken from the session default. It is always a hard deadline; use
        # `attempt_timeout=` to bound each individual try so retries/rotations
        # fire instead of one hung attempt eating the whole budget.
        if req_timeout is not None:
            timeout_secs = (
                req_timeout.total_seconds()
                if hasattr(req_timeout, "total_seconds")
                else float(req_timeout)
            )
        else:
            timeout_secs = self.timeout.total_seconds()
        deadline = start_time + timeout_secs

        # Per-attempt timeout: bounds each individual wreq attempt so
        # retries/rotations can fire within the total budget. The
        # per-request value overrides the session default.
        if req_attempt_timeout is None:
            req_attempt_timeout = self.attempt_timeout
        if req_attempt_timeout is not None:
            attempt_secs = (
                req_attempt_timeout.total_seconds()
                if hasattr(req_attempt_timeout, "total_seconds")
                else float(req_attempt_timeout)
            )
        else:
            attempt_secs = None  # no per-attempt cap (legacy behavior)

        # Opera Mini: bypass wreq entirely, use stdlib urllib (OpenSSL).
        # No challenge detection, no fingerprint rotation, no retries.
        # Opera Mini is a no-JS proxy browser — only GET navigations.
        if self._profile is Profile.OPERA_MINI:
            if method.upper() != "GET":
                raise ValueError(
                    f"Opera Mini profile only supports GET, got {method!r}"
                )
            domain = extract_domain(url) or url
            if self._rate_limiter:
                await self._rate_limiter.wait_async(domain)
            logger.debug("%s %s (Opera Mini)", method, url)
            timeout = timeout_secs
            loop = asyncio.get_event_loop()
            status, resp_headers, text, final_url, set_cookies = (
                await loop.run_in_executor(
                    None,
                    lambda: self._om_identity.request(
                        url, headers=extra_headers, timeout=timeout,
                        max_size=max_response_size,
                    ),
                )
            )
            if self._rate_limiter:
                self._rate_limiter.record(domain)
            return WaferResponse(
                status_code=status,
                content=text.encode("utf-8"),
                text=text,
                headers=resp_headers,
                url=final_url,
                elapsed=time.monotonic() - start_time,
                was_retried=False,
                challenge_type=None,
                emulation=self._serving_emulation_repr(),
                raw=None,
                raw_set_cookie=set_cookies,
            )

        state = RetryState(self.max_retries, self.max_rotations)
        m = _to_method(method) if isinstance(method, str) else method
        domain = extract_domain(url) or url
        current_url = url

        browser_attempted_type: str | None = None
        native_attempted = False
        native_retries = 0
        redirects_followed = 0
        history: list[HistoryEntry] = []

        logger.debug("%s %s", method, url)

        while True:
            # Per-request deadline: abort retry loop if exceeded
            if deadline is not None and time.monotonic() > deadline:
                raise WaferTimeout(url, timeout_secs)

            # Rate limiting: wait if too soon since last request to this domain
            if self._rate_limiter:
                await self._rate_limiter.wait_async(domain)

            # Sticky native-TLS: this host was proven to need OpenSSL
            # (Imperva fingerprints wreq's BoringSSL stack and challenges it
            # even with valid cookies). Route straight through urllib — and
            # the native jar, not wreq's, holds the WAF cookies.
            if domain in self._native_tls_domains:
                native_resp = await self._try_native_tls(
                    method, current_url, extra_headers, kwargs,
                    deadline, start_time, state, max_response_size,
                )
                if native_resp is not None:
                    native_resp.history = history
                if native_resp is not None and native_resp.challenge_type is None:
                    if self._rate_limiter:
                        self._rate_limiter.record(domain)
                    self._record_success(domain)
                    self._record_url(current_url)
                    return native_resp
                # Transport error or a transient (rate-based) reese84 page.
                # OpenSSL is the only path that works for this pinned host, so
                # back off and retry native rather than reverting to wreq
                # (which is always challenged). The loop-top deadline check
                # bounds total wait.
                native_retries += 1
                if native_retries <= NATIVE_MAX_RETRIES:
                    delay = calculate_backoff(
                        native_retries - 1, base=2.0, max_delay=15.0
                    )
                    if deadline is not None:
                        delay = min(delay, max(0.0, deadline - time.monotonic()))
                    logger.debug(
                        "Native-TLS retry %d/%d for %s in %.1fs",
                        native_retries, NATIVE_MAX_RETRIES, current_url, delay,
                    )
                    await asyncio.sleep(delay)
                    continue
                if native_resp is None:
                    raise ConnectionFailed(
                        current_url, "native-TLS request failed"
                    )
                # Native retries exhausted on a persistent reese84 challenge
                # (the heavy state where even OpenSSL must present a token).
                # If a browser is available, un-pin and fall back to the wreq
                # path: it escalates to the browser solve, which earns a
                # reese84 token that wreq then carries through. Without a
                # browser there's no way to mint the token, so surface it.
                if self._browser_solver is not None:
                    logger.info(
                        "Native-TLS exhausted at %s; reverting to "
                        "wreq + browser solve",
                        current_url,
                    )
                    self._native_tls_domains.discard(domain)
                    native_attempted = True
                    # Skip the wreq fingerprint rotations (Safari is also
                    # BoringSSL and also challenged here) so the next wreq
                    # attempt goes straight to the last-resort browser solve.
                    state.rotation_retries = state.max_rotations
                    # fall through to the wreq request below
                # No browser to mint the reese84 token. Mirror the usual
                # contract: under no-rotation/.bulk() return the challenge
                # response, otherwise raise.
                elif self.max_rotations == 0:
                    if self._rate_limiter:
                        self._rate_limiter.record(domain)
                    return native_resp
                else:
                    raise ChallengeDetected(
                        native_resp.challenge_type
                        or ChallengeType.IMPERVA.value,
                        current_url,
                        native_resp.status_code,
                        response=native_resp,
                    )

            # TLS session rotation for unlinkable requests
            if self._rotate_every:
                async with self._rotate_lock:
                    self._request_count += 1
                    if self._request_count % self._rotate_every == 0:
                        self._rebuild_client()

            # Rebuild merged headers each iteration (fingerprint may rotate)
            kwargs["headers"] = self._build_headers(
                current_url, extra_headers, method=method
            )

            # Clamp per-attempt timeout to remaining deadline so a
            # single slow response can't overshoot the user's budget.
            # attempt_timeout additionally caps each individual try
            # (clamped to the remaining total budget when both are set).
            attempt_limit = None
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise WaferTimeout(url, timeout_secs)
                attempt_limit = min(timeout_secs, remaining)
            if attempt_secs is not None:
                attempt_limit = (
                    attempt_secs
                    if attempt_limit is None
                    else min(attempt_secs, attempt_limit)
                )
            if attempt_limit is not None:
                kwargs["timeout"] = datetime.timedelta(
                    seconds=attempt_limit
                )

            # Make the request
            try:
                resp = await self._client.request(
                    m, current_url, **kwargs
                )
            except Exception as e:
                # An attempt bounded by attempt_timeout that hits the
                # wreq-layer timeout is retryable by design: the
                # per-attempt cap exists precisely so retries/rotations
                # can fire instead of one hung attempt eating the whole
                # budget. The loop-top deadline check still bounds the
                # total time.
                attempt_timed_out = (
                    attempt_secs is not None
                    and isinstance(e, wreq.exceptions.TimeoutError)
                )
                if not state.can_retry:
                    # Normal retries exhausted. A timed-out attempt may
                    # still consume rotation budget: a hanging connection
                    # is often fingerprint-linked (WAF tarpit), so a
                    # fresh TLS identity can escape it.
                    if attempt_timed_out and state.can_rotate:
                        # Mirror the 403/429 path: a hung attempt is a failure
                        # strike, so a persistent tarpit accrues strikes and
                        # eventually retires the session (gated the same way -
                        # check budget first, retire on the threshold).
                        should_retire = self._record_failure(domain)
                        state.use_rotation()
                        if should_retire:
                            await self._retire_session(domain)
                            delay = self._rotation_delay()
                            if deadline is not None:
                                delay = min(
                                    delay,
                                    max(0.0, deadline - time.monotonic()),
                                )
                            logger.debug(
                                "Attempt timed out after %.1fs, retired "
                                "session, retrying in %.1fs",
                                attempt_secs,
                                delay,
                            )
                            await asyncio.sleep(delay)
                            continue
                        pinned = (
                            self._fingerprint is not None
                            and self._fingerprint.pinned
                        )
                        # Mirror the 403 path: clear cookies (unless pinned)
                        # and advance the cross-family ladder / fingerprint_pool
                        # rather than only cycling Chrome versions. Going
                        # through _advance_rotation keeps self.headers coherent
                        # with the TLS identity for non-Chrome sessions.
                        if self._cookie_cache and not pinned:
                            await asyncio.to_thread(
                                self._cookie_cache.clear, domain
                            )
                        if not pinned:
                            self._advance_rotation(state.rotation_retries)
                        self._rebuild_client()
                        delay = self._rotation_delay()
                        if deadline is not None:
                            delay = min(
                                delay,
                                max(0.0, deadline - time.monotonic()),
                            )
                        logger.debug(
                            "Attempt timed out after %.1fs, rotated "
                            "(rotation %d/%d), retrying in %.1fs",
                            attempt_secs,
                            state.rotation_retries,
                            state.max_rotations,
                            delay,
                        )
                        await asyncio.sleep(delay)
                        continue
                    if attempt_timed_out:
                        # Report the explicit per-request total budget if one
                        # was set, else the per-attempt cap that exhausted us
                        # (a session-default timeout is not the headline here).
                        raise WaferTimeout(
                            current_url,
                            timeout_secs
                            if req_timeout is not None
                            else attempt_secs,
                        ) from e
                    raise ConnectionFailed(
                        current_url, str(e)
                    ) from e
                state.use_retry()
                delay = calculate_backoff(state.normal_retries - 1)
                if deadline is not None:
                    delay = min(
                        delay, max(0.0, deadline - time.monotonic())
                    )
                logger.debug(
                    "Connection error, retry %d/%d in %.1fs: %s",
                    state.normal_retries, state.max_retries, delay, e,
                )
                await asyncio.sleep(delay)
                continue

            status = resp.status.as_int()

            # Record request timestamp for rate limiting
            if self._rate_limiter:
                self._rate_limiter.record(domain)

            # 3xx → follow redirect
            if (
                self.follow_redirects
                and 300 <= status < 400
                and status != 304
            ):
                location = _extract_location(resp.headers)
                if location:
                    if redirects_followed >= self.max_redirects:
                        raise TooManyRedirects(
                            current_url, self.max_redirects
                        )
                    new_url = self._resolve_redirect_url(
                        current_url, location
                    )
                    redirects_followed += 1
                    # Record the hop: the 3xx status and the URL that
                    # returned it (requests-style history chain).
                    history.append(HistoryEntry(status, current_url))
                    logger.debug(
                        "%d redirect %d/%d: %s → %s",
                        status,
                        redirects_followed,
                        self.max_redirects,
                        current_url,
                        new_url,
                    )
                    # Track referer from pre-redirect URL
                    self._record_url(current_url)
                    cross_origin = self._is_cross_origin(
                        current_url, new_url
                    )
                    current_url = new_url
                    domain = (
                        extract_domain(current_url) or current_url
                    )
                    # A redirect to a new host gets its own native-TLS probe
                    # budget (Imperva often bounces between portal and API
                    # subdomains; the target may need the bypass too).
                    if cross_origin:
                        native_attempted = False
                        native_retries = 0
                    # POST redirects (301, 302, 303) → GET per RFC
                    method_changed = False
                    if status in (301, 302, 303) and m != Method.GET:
                        m = Method.GET
                        method = "GET"
                        kwargs.pop("body", None)
                        kwargs.pop("form", None)
                        kwargs.pop("json", None)
                        method_changed = True
                    # Strip sensitive headers on cross-origin or
                    # body headers on method change (Fetch spec)
                    if cross_origin or method_changed:
                        extra_headers = self._strip_sensitive_headers(
                            extra_headers, cross_origin, method_changed
                        )
                    continue

            # Decode headers eagerly for all remaining paths
            headers = _decode_headers(resp.headers)
            was_retried = (
                state.normal_retries > 0
                or state.rotation_retries > 0
                or browser_attempted_type is not None
            )

            # Response-size cap: short-circuit on a declared Content-Length
            # over the cap before reading the body at all.
            if max_response_size is not None:
                declared = _content_length_over_cap(resp, max_response_size)
                if declared is not None:
                    raise ResponseTooLarge(
                        current_url, declared, max_response_size
                    )

            # Read body: wreq's bytes() returns the DECOMPRESSED body
            # (gzip/br/zstd already handled), so raw_content is the true
            # byte stream. Text content is decoded charset-aware (header
            # charset -> <meta charset> sniff -> UTF-8) -- the same
            # resolution WaferResponse.text uses -- instead of wreq's
            # text(), which never meta-sniffs.
            is_binary = _is_binary_content_type(
                headers.get("content-type", "")
            )
            try:
                if max_response_size is not None:
                    # Streamed early-abort: stop the moment the running total
                    # passes the cap, never buffering the whole oversize body.
                    raw_content = await _aread_body_capped(
                        resp, max_response_size
                    )
                else:
                    raw_content = await resp.bytes()
                if is_binary:
                    body = None
                else:
                    body = raw_content.decode(
                        resolve_charset(headers, raw_content),
                        errors="replace",
                    )
            except _CapExceeded as ce:
                raise ResponseTooLarge(
                    current_url, ce.size, max_response_size
                ) from None
            except Exception as e:
                # Decompression errors (e.g. malformed gzip from eBay)
                if not state.can_retry:
                    raise ConnectionFailed(
                        current_url, f"body decode: {e}"
                    ) from e
                state.use_retry()
                delay = calculate_backoff(state.normal_retries - 1)
                logger.debug(
                    "Body decode error, retry %d/%d in %.1fs: %s",
                    state.normal_retries, state.max_retries, delay, e,
                )
                await asyncio.sleep(delay)
                continue

            # 5xx → backoff + normal retry
            if 500 <= status < 600:
                if not state.can_retry:
                    return self._make_response(
                        status_code=status,
                        content=raw_content,
                        text=body,
                        headers=headers,
                        url=current_url,
                        start_time=start_time,
                        was_retried=was_retried,
                        state=state,
                        history=history,
                        raw=resp,
                    )
                state.use_retry()
                delay = calculate_backoff(state.normal_retries - 1)
                logger.debug(
                    "%d server error, retry %d/%d in %.1fs",
                    status, state.normal_retries, state.max_retries, delay,
                )
                await asyncio.sleep(delay)
                continue

            # Challenge detection (HTML responses only — WAF challenges
            # are always HTML pages). Skip for:
            # - Binary content (images, PDFs, etc.)
            # - Non-HTML text (JSON, XML) — API endpoints may have
            #   challenge markers in cookies/headers but browser-solving
            #   the API URL itself can't work (renders raw JSON).
            # - Opera Mini / Dart -- non-browser profiles.
            content_type = headers.get("content-type", "")
            challenge = (
                detect_challenge(status, headers, body)
                if body is not None
                and self._profile not in (Profile.OPERA_MINI, Profile.DART)
                and _is_challengeable_content_type(content_type)
                else None
            )

            # 429 without detected challenge → rate limit retry
            if status == 429 and challenge is None:
                retry_after = parse_retry_after(
                    headers.get("retry-after", "")
                )
                if not state.can_rotate:
                    if self.max_rotations == 0:
                        return self._make_response(
                            status_code=status,
                            content=raw_content,
                            text=body,
                            headers=headers,
                            url=current_url,
                            start_time=start_time,
                            was_retried=was_retried,
                            state=state,
                            history=history,
                            raw=resp,
                        )
                    raise RateLimited(
                        current_url,
                        retry_after,
                        response=self._make_response(
                            status_code=status,
                            content=raw_content,
                            text=body,
                            headers=headers,
                            url=current_url,
                            start_time=start_time,
                            was_retried=was_retried,
                            state=state,
                            history=history,
                            raw=resp,
                        ),
                    )

                # Session health: track failure (only retire if
                # we still have budget — avoids destroying state
                # right before raising)
                retired = self._record_failure(domain)
                if retired:
                    await self._retire_session(domain)

                state.use_rotation()
                # Advance the identity BEFORE computing the rotation delay so
                # that _rotation_delay() (pool mode) reads the INCOMING
                # identity's strike count, not the outgoing just-failed one --
                # matching the 403 / empty-200 paths. Sleep stays after the
                # advance.
                if not retired:
                    # Clear domain cookies on rotation unless the
                    # fingerprint is pinned (browser-solve matched the
                    # emulation to the browser's TLS identity, so the
                    # cookies belong to THIS fingerprint).
                    pinned = (
                        self._fingerprint is not None
                        and self._fingerprint.pinned
                    )
                    if self._cookie_cache and not pinned:
                        await asyncio.to_thread(
                            self._cookie_cache.clear, domain
                        )
                    if not pinned:
                        # Cross-family ladder (or fingerprint_pool when set).
                        # rotation 1 = fresh TLS session on the same family;
                        # 2+ escalate Firefox -> Safari -> Edge -> version
                        # cycling, swapping the header envelope on each family
                        # switch. Pinned = keep the TLS identity the cookies
                        # are bound to (browser-solve matched the emulation).
                        self._advance_rotation(state.rotation_retries)
                    self._rebuild_client()
                rotation_floor = self._rotation_delay()
                delay = (
                    max(retry_after, rotation_floor)
                    if retry_after is not None
                    else rotation_floor
                )
                logger.debug(
                    "429 rate limited, waiting %.1fs (rotation %d/%d)",
                    delay, state.rotation_retries, state.max_rotations,
                )
                await asyncio.sleep(delay)
                continue

            # Challenge or bare 403 → try inline solver, then rotate
            if challenge is not None or (
                status == 403 and body is not None
            ):
                # Session health: track failure (defer retirement
                # until after budget check to avoid destroying
                # state before raising)
                should_retire = self._record_failure(domain)

                # Try inline solver first (no fingerprint rotation,
                # does NOT consume rotation budget — separate cap)
                if (
                    challenge is not None
                    and state.inline_solves < state.max_inline_solves
                    and await self._try_inline_solve(
                        challenge, body, current_url
                    )
                ):
                    state.inline_solves += 1
                    delay = calculate_backoff(
                        state.inline_solves - 1,
                        base=0.5,
                        max_delay=10.0,
                    )
                    logger.debug(
                        "%s solved inline at %s (%d/%d), "
                        "retrying in %.1fs",
                        challenge.value,
                        current_url,
                        state.inline_solves,
                        state.max_inline_solves,
                        delay,
                    )
                    await asyncio.sleep(delay)
                    continue

                # Imperva: try the native-TLS (OpenSSL) bypass before
                # burning rotations or a browser. Imperva free-passes
                # non-BoringSSL clients that omit Sec-Fetch-*; wreq can't
                # be one, urllib can. On success, pin this host to native.
                if (
                    challenge == ChallengeType.IMPERVA
                    and domain not in self._native_tls_domains
                    and not native_attempted
                    and self._native_tls_usable()
                ):
                    native_attempted = True
                    native_resp = await self._try_native_tls(
                        method, current_url, extra_headers, kwargs,
                        deadline, start_time, state, max_response_size,
                    )
                    if native_resp is not None:
                        native_resp.history = history
                    # A non-challenge reply means the OpenSSL client got past
                    # the WAF — pin the host regardless of HTTP status (a real
                    # 404/500 from the origin still proves the bypass works).
                    if (
                        native_resp is not None
                        and native_resp.challenge_type is None
                    ):
                        self._native_tls_domains.add(domain)
                        if self._rate_limiter:
                            self._rate_limiter.record(domain)
                        self._record_success(domain)
                        self._record_url(current_url)
                        logger.info(
                            "Imperva bypassed via native-TLS at %s "
                            "(host pinned)",
                            current_url,
                        )
                        return native_resp
                    logger.debug(
                        "Native-TLS did not bypass Imperva at %s",
                        current_url,
                    )
                    # Fingerprint rotation can't help an Imperva TLS-stack
                    # challenge (Safari is BoringSSL too, and re-challenged),
                    # so when a browser is available skip the rotations and go
                    # straight to the last-resort browser solve below.
                    if self._browser_solver is not None:
                        state.rotation_retries = state.max_rotations

                # Early browser solve for JS-only challenges (rotation
                # can't help — these require JS execution)
                if (
                    challenge is not None
                    and challenge in JS_ONLY_CHALLENGES
                    and browser_attempted_type != challenge.value
                    and self._browser_solver is not None
                ):
                    browser_attempted_type = challenge.value
                    browser_result = await self._try_browser_solve(
                        challenge, current_url, deadline,
                        embedder=self._imperva_embedder(
                            challenge, current_url, extra_headers, kwargs
                        ),
                        replay=self._browser_replay(method, kwargs),
                        max_size=max_response_size,
                    )
                    if isinstance(browser_result, WaferResponse):
                        self._record_success(domain)
                        self._record_url(current_url)
                        browser_result.elapsed = (
                            time.monotonic() - start_time
                        )
                        browser_result.history = history
                        return browser_result
                    if browser_result:
                        # Browser solved and injected cookies — reset
                        # failure counter so the retry starts clean.
                        self._record_success(domain)
                        continue

                # No browser solver — rotation can't help JS-only challenges
                if (
                    self._browser_solver is None
                    and challenge in JS_ONLY_CHALLENGES
                ):
                    if self.max_rotations == 0:
                        return self._make_response(
                            status_code=status,
                            content=raw_content,
                            text=body,
                            headers=headers,
                            url=current_url,
                            start_time=start_time,
                            was_retried=was_retried,
                            challenge_type=challenge.value,
                            state=state,
                            history=history,
                            raw=resp,
                        )
                    raise ChallengeDetected(
                        challenge.value,
                        current_url,
                        status,
                        response=self._make_response(
                            status_code=status,
                            content=raw_content,
                            text=body,
                            headers=headers,
                            url=current_url,
                            start_time=start_time,
                            was_retried=was_retried,
                            challenge_type=challenge.value,
                            state=state,
                            history=history,
                            raw=resp,
                        ),
                    )

                # Fallback: rotate fingerprint
                if not state.can_rotate:
                    # Last resort: browser solve (once per challenge type)
                    if (
                        challenge is not None
                        and browser_attempted_type != challenge.value
                        and self._browser_solver is not None
                    ):
                        browser_attempted_type = challenge.value
                        browser_result = (
                            await self._try_browser_solve(
                                challenge, current_url, deadline,
                                embedder=self._imperva_embedder(
                                    challenge, current_url,
                                    extra_headers, kwargs,
                                ),
                                replay=self._browser_replay(method, kwargs),
                                max_size=max_response_size,
                            )
                        )
                        if isinstance(browser_result, WaferResponse):
                            self._record_success(domain)
                            self._record_url(current_url)
                            browser_result.elapsed = (
                                time.monotonic() - start_time
                            )
                            browser_result.history = history
                            return browser_result
                        if browser_result:
                            self._record_success(domain)
                            continue
                    if challenge:
                        if self.max_rotations == 0:
                            return self._make_response(
                                status_code=status,
                                content=raw_content,
                                text=body,
                                headers=headers,
                                url=current_url,
                                start_time=start_time,
                                was_retried=was_retried,
                                challenge_type=challenge.value,
                                state=state,
                                history=history,
                                raw=resp,
                            )
                        raise ChallengeDetected(
                            challenge.value,
                            current_url,
                            status,
                            response=self._make_response(
                                status_code=status,
                                content=raw_content,
                                text=body,
                                headers=headers,
                                url=current_url,
                                start_time=start_time,
                                was_retried=was_retried,
                                challenge_type=challenge.value,
                                state=state,
                                history=history,
                                raw=resp,
                            ),
                        )
                    return self._make_response(
                        status_code=status,
                        content=raw_content,
                        text=body,
                        headers=headers,
                        url=current_url,
                        start_time=start_time,
                        was_retried=was_retried,
                        state=state,
                        history=history,
                        raw=resp,
                    )
                state.use_rotation()
                if should_retire:
                    await self._retire_session(domain)
                else:
                    # Clear domain cookies on rotation unless the
                    # fingerprint is pinned (browser-solve matched the
                    # emulation, so cookies belong to THIS fingerprint).
                    pinned = (
                        self._fingerprint is not None
                        and self._fingerprint.pinned
                    )
                    if self._cookie_cache and not pinned:
                        await asyncio.to_thread(
                            self._cookie_cache.clear, domain
                        )
                    if not pinned:
                        # Cross-family ladder (or fingerprint_pool when set).
                        # rotation 1 = fresh TLS session on the same family;
                        # 2+ escalate Firefox -> Safari -> Edge -> version
                        # cycling, swapping the header envelope on each family
                        # switch. Pinned = keep the TLS identity the cookies
                        # are bound to (browser-solve matched the emulation).
                        self._advance_rotation(state.rotation_retries)
                    self._rebuild_client()
                delay = self._rotation_delay()
                logger.debug(
                    "%s at %s, rotated (rotation %d/%d), "
                    "waiting %.1fs",
                    challenge.value if challenge else "403",
                    current_url,
                    state.rotation_retries,
                    self.max_rotations,
                    delay,
                )
                await asyncio.sleep(delay)
                continue

            # 200 with empty text body → normal retry (skip for binary)
            if (
                body is not None
                and status == 200
                and not body.strip()
            ):
                if not state.can_retry:
                    # max_retries=0 / .bulk(): the documented contract is to
                    # RETURN the empty-200 response, never to rotate. This must
                    # be checked BEFORE the 200-capable rotation branch below,
                    # which would otherwise rotate a max_retries=0 caller that
                    # still has rotation budget.
                    if self.max_retries == 0:
                        return self._make_response(
                            status_code=status,
                            content=raw_content,
                            text=body,
                            headers=headers,
                            url=current_url,
                            start_time=start_time,
                            was_retried=was_retried,
                            state=state,
                            history=history,
                            raw=resp,
                        )
                    # Empty 200 from a host that ALREADY served real content
                    # this session is bell's primary "this identity is hot"
                    # signal. Once same-identity retries are spent, escalate to
                    # a fresh identity (within max_rotations) before giving up:
                    # a different fingerprint often gets the real body back.
                    if (
                        domain in self._body_capable_domains
                        and state.can_rotate
                    ):
                        state.use_rotation()
                        pinned = (
                            self._fingerprint is not None
                            and self._fingerprint.pinned
                        )
                        if self._cookie_cache and not pinned:
                            await asyncio.to_thread(
                                self._cookie_cache.clear, domain
                            )
                        if not pinned:
                            self._advance_rotation(state.rotation_retries)
                        self._rebuild_client()
                        delay = self._rotation_delay()
                        logger.debug(
                            "Empty 200 from 200-capable host %s, rotated "
                            "(rotation %d/%d), retrying in %.1fs",
                            domain,
                            state.rotation_retries,
                            self.max_rotations,
                            delay,
                        )
                        await asyncio.sleep(delay)
                        continue
                    raise EmptyResponse(
                        current_url,
                        status,
                        response=self._make_response(
                            status_code=status,
                            content=raw_content,
                            text=body,
                            headers=headers,
                            url=current_url,
                            start_time=start_time,
                            was_retried=was_retried,
                            state=state,
                            history=history,
                            raw=resp,
                        ),
                    )
                state.use_retry()
                delay = calculate_backoff(state.normal_retries - 1)
                logger.debug(
                    "Empty 200 body, retry %d/%d in %.1fs",
                    state.normal_retries, state.max_retries, delay,
                )
                await asyncio.sleep(delay)
                continue

            # Success — reset failure counter, pin fingerprint, track URL
            self._record_success(domain)
            self._record_url(current_url)
            # Mark host 200-capable (non-empty 2xx body) so a later empty 200
            # is treated as an identity-hot signal worth a rotation.
            if 200 <= status < 300 and body and body.strip():
                self._body_capable_domains.add(domain)
            if state.rotation_retries > 0 and self._fingerprint is not None:
                self._fingerprint.pin()

            return self._make_response(
                status_code=status,
                content=raw_content,
                text=body,
                headers=headers,
                url=current_url,
                start_time=start_time,
                was_retried=was_retried,
                state=state,
                history=history,
                raw=resp,
            )

    async def get(self, url: str, **kwargs) -> WaferResponse:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> WaferResponse:
        return await self.request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs) -> WaferResponse:
        return await self.request("PUT", url, **kwargs)

    async def delete(self, url: str, **kwargs) -> WaferResponse:
        return await self.request("DELETE", url, **kwargs)

    async def head(self, url: str, **kwargs) -> WaferResponse:
        return await self.request("HEAD", url, **kwargs)

    async def options(self, url: str, **kwargs) -> WaferResponse:
        return await self.request("OPTIONS", url, **kwargs)

    async def patch(self, url: str, **kwargs) -> WaferResponse:
        return await self.request("PATCH", url, **kwargs)

    def add_cookie(self, raw_set_cookie: str, url: str) -> None:
        """Inject a Set-Cookie header value into the session's cookie jar."""
        if self._profile is Profile.OPERA_MINI:
            raise NotImplementedError(
                "add_cookie() is not supported with Opera Mini profile"
            )
        self._client.cookie_jar.add(raw_set_cookie, url)

    async def mint_recaptcha_v3(
        self,
        sitekey: str,
        action: str,
        *,
        origin: str | None = None,
        referer: str | None = None,
        v: str | None = None,
        enterprise: bool = False,
    ) -> str:
        """Mint a browser-free reCAPTCHA v3 score token.

        Async parity of :meth:`SyncSession.mint_recaptcha_v3`. Performs
        the cross-origin anchor + reload flow against Google's reCAPTCHA
        endpoints using this session's own TLS-emulated client, so the
        token is minted under a real browser fingerprint. This is
        reCAPTCHA v3 (score tokens) -- distinct from the browser-based v2
        grid solver.

        Args:
            sitekey: the site's reCAPTCHA key (readable from the page).
            action: the action name (rides in the ``sa`` reload param).
            origin: site origin the sitekey is bound to, e.g.
                ``https://www.example.com``. If None, derived from
                ``referer``.
            referer: the page embedding the widget; defaults to ``origin``.
            v: the api.js release token. If None, scraped from Google's
                api.js (or enterprise.js) and cached on the session.
            enterprise: use the reCAPTCHA Enterprise anchor/reload paths
                and enterprise.js instead of the standard v3 paths.

        Returns:
            The reCAPTCHA response token (a non-empty string).

        Raises:
            TokenMintFailed: if an anchor/reload/api.js token cannot be
                extracted, or an endpoint returns a non-200 status. Never
                silently returns None.

        Note:
            Minting always produces a token, but the *score* Google
            assigns depends on request reputation (IP, TLS, cookies).
            wafer mints the token; it cannot guarantee the site's score
            threshold passes.
        """
        from wafer import _recaptcha_v3

        cache_key = "ent" if enterprise else "std"

        async def scrape_v() -> str:
            cached = self._recaptcha_v.get(cache_key)
            if cached is not None:
                return cached
            scraped = await _recaptcha_v3._scrape_v_async(
                self.request, enterprise
            )
            self._recaptcha_v[cache_key] = scraped
            return scraped

        # Suspend embed mode for the cross-origin Google requests: in embed
        # mode the client-level Accept / X-Requested-With would leak to or
        # duplicate against google.com. No-op for a non-embed session.
        # (_embed_suspended is sync: it only rebuilds the client, never
        # awaits, so wrapping the awaited mint in a `with` is correct.)
        with self._embed_suspended():
            return await _recaptcha_v3.mint_async(
                self.request,
                sitekey,
                action,
                origin=origin,
                referer=referer,
                v=v,
                enterprise=enterprise,
                scrape_v=scrape_v,
            )

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        # Close the browser solver only if this session created it.
        # A solver passed in via browser_solver= is shared: closing it
        # here would tear it down for every other session holding it.
        if self._browser_solver is not None and self._owns_solver:
            try:
                self._browser_solver.close()
            except Exception:
                logger.debug("BrowserSolver.close() failed", exc_info=True)
