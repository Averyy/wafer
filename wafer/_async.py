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
    _browser_attempt_timeout,
    _browser_solve_timeout,
    _callable_accepts_keyword,
    _canonicalize_url_host,
    _CapExceeded,
    _connection_failure_reason,
    _content_length_over_cap,
    _decode_headers,
    _extract_location,
    _is_binary_content_type,
    _is_challengeable_content_type,
    _tmd_browser_attempt_count,
    _tmd_browser_attempt_timeout,
    _tmd_punish_url_from_body,
    _to_method,
)
from wafer._challenge import (
    JS_ONLY_CHALLENGES,
    TERMINAL_CHALLENGES,
    ChallengeType,
    detect_challenge,
)
from wafer._cookies import (
    browser_cookie_matches_host,
    extract_domain,
    registrable_domain,
)
from wafer._errors import (
    ChallengeDetected,
    ConnectionFailed,
    EmptyResponse,
    RateLimited,
    RequestBlocked,
    ResponseTooLarge,
    TooManyRedirects,
    WaferTimeout,
)
from wafer._fingerprint import (
    chrome_full_version_from_ua,
    chrome_version_from_ua,
)
from wafer._native_tls import NATIVE_MAX_RETRIES
from wafer._profiles import Profile
from wafer._response import HistoryEntry, WaferResponse, resolve_charset
from wafer._retry import RetryState, calculate_backoff, parse_retry_after
from wafer._solvers import (
    REDDIT_CACHE_DOMAIN,
    REDDIT_GATE_MAX_BYTES,
    REDDIT_VERIFICATION_MAX_BYTES,
    parse_amazon_captcha,
    parse_reddit_verification,
    reddit_cookie_names,
    reddit_has_cookie_evidence,
    reddit_solve_origin,
    reddit_submission_url,
    solve_acw,
    tmd_homepage_url,
)

logger = logging.getLogger("wafer")


class AsyncSession(BaseSession):
    """Asynchronous HTTP session with anti-detection defaults."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._client_generation = 0
        if self._profile is Profile.OPERA_MINI:
            self._client = None  # Opera Mini bypasses wreq entirely
        else:
            self._client = wreq.Client(**self._build_client_kwargs())
            self._hydrate_jar_from_cache()
        self._rotate_lock = asyncio.Lock()
        self._reddit_bootstrap_lock = asyncio.Lock()
        self._reddit_bootstrap_generation = 0
        self._reddit_bootstrap_client_generation: int | None = None

    def _hydrate_jar_from_cache(self) -> None:
        """Load cached cookies from disk into the client's jar."""
        if self._cookie_cache is None:
            return
        try:
            for domain in self._cookie_cache.list_domains():
                cookies = self._cookie_cache.load(domain)
                for cookie in cookies:
                    try:
                        self._record_cookie_scope(cookie["raw"], cookie["url"])
                        self._client.cookie_jar.add(cookie["raw"], cookie["url"])
                    except Exception as exc:
                        logger.debug(
                            "Failed to hydrate cookie %s (%s)",
                            cookie.get("name", "?"),
                            type(exc).__name__,
                        )
        except Exception:
            logger.debug("Failed to hydrate cookies from cache")

    async def _cache_response_cookies(
        self,
        url: str,
        resp,
        cache_domain: str | None = None,
    ) -> None:
        """Write-through: save Set-Cookie headers to disk cache."""
        raw_cookies = self._record_response_cookie_scopes(url, resp)
        if self._cookie_cache is None:
            return
        try:
            domain = cache_domain or extract_domain(url)
            if not domain:
                return
            if raw_cookies:
                await asyncio.to_thread(
                    self._cookie_cache.save_from_headers,
                    domain,
                    raw_cookies,
                    url,
                )
        except Exception:
            logger.debug("Failed to cache response cookies")

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
        self._client_generation += 1
        self._hydrate_jar_from_cache()
        logger.debug("Client rebuilt with emulation=%s", self.emulation)

    async def _retire_session(self, domain: str) -> None:
        """Full identity reset: new fingerprint, empty jar, clear cache."""
        # Restore Chrome if rotated to Safari (not explicit Safari profile)
        if self._safari_identity is not None and self._profile is not Profile.SAFARI:
            self._switch_to_chrome()
        if self._fingerprint is not None:
            self._fingerprint.reset()
        if self._cookie_cache:
            await asyncio.to_thread(self._clear_cached_cookies, domain)
        self._client = wreq.Client(**self._build_client_kwargs())
        self._client_generation += 1
        self._hydrate_jar_from_cache()
        self._domain_failures.pop(domain, None)
        logger.warning(
            "Session retired for %s: emulation=%s",
            domain,
            self.emulation,
        )

    @staticmethod
    def _reddit_subrequest_kwargs(
        url: str,
        deadline: float | None,
        total_timeout: float,
    ) -> dict:
        if deadline is None:
            return {}
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise WaferTimeout(url, total_timeout)
        return {"timeout": datetime.timedelta(seconds=remaining)}

    def _reddit_client_changed(self, client, generation: int) -> bool:
        return client is not self._client or generation != self._client_generation

    async def _reddit_bootstrap_on_client(
        self,
        client,
        client_generation: int,
        url: str,
        deadline: float | None,
        total_timeout: float,
    ) -> bool | None:
        """Solve on one captured client; None means the client changed."""
        origin = reddit_solve_origin(url)
        if origin is None:
            return False
        try:
            verification_resp = await client.get(
                origin,
                **self._reddit_subrequest_kwargs(url, deadline, total_timeout),
            )
            if self._reddit_client_changed(client, client_generation):
                return None
            verification_cookies = verification_resp.headers.get_all("set-cookie")
            await self._cache_response_cookies(
                origin,
                verification_resp,
                cache_domain=REDDIT_CACHE_DOMAIN,
            )
            if self._reddit_client_changed(client, client_generation):
                await asyncio.to_thread(
                    self._clear_cached_cookies,
                    REDDIT_CACHE_DOMAIN,
                )
                return None
            if not 200 <= verification_resp.status.as_int() < 300:
                logger.debug("Reddit bootstrap failed due to verification status")
                return False
            if reddit_has_cookie_evidence(reddit_cookie_names(verification_cookies)):
                logger.info("Reddit anonymous cookies established")
                return True

            logger.info("Reddit verification page fetched")
            try:
                verification_body = (
                    await _aread_body_capped(
                        verification_resp,
                        REDDIT_VERIFICATION_MAX_BYTES,
                    )
                ).decode("utf-8")
            except (_CapExceeded, UnicodeDecodeError):
                logger.debug("Reddit bootstrap failed due to verification structure")
                return False
            if self._reddit_client_changed(client, client_generation):
                return None
            verification = parse_reddit_verification(verification_body)
            if verification is None:
                logger.debug("Reddit bootstrap failed due to verification structure")
                return False

            submission_url = reddit_submission_url(verification)
            solved_resp = await client.get(
                submission_url,
                **self._reddit_subrequest_kwargs(url, deadline, total_timeout),
            )
            if self._reddit_client_changed(client, client_generation):
                return None
            solved_cookies = solved_resp.headers.get_all("set-cookie")
            await self._cache_response_cookies(
                origin,
                solved_resp,
                cache_domain=REDDIT_CACHE_DOMAIN,
            )
            if self._reddit_client_changed(client, client_generation):
                await asyncio.to_thread(
                    self._clear_cached_cookies,
                    REDDIT_CACHE_DOMAIN,
                )
                return None
            if not 200 <= solved_resp.status.as_int() < 300:
                logger.debug("Reddit bootstrap failed due to submission status")
                return False
            if not reddit_has_cookie_evidence(reddit_cookie_names(solved_cookies)):
                logger.debug("Reddit bootstrap failed due to cookie evidence")
                return False
            logger.info("Reddit verification submitted")
            logger.info("Reddit anonymous cookies established")
            return True
        except WaferTimeout:
            raise
        except Exception:
            if deadline is not None and time.monotonic() >= deadline:
                raise WaferTimeout(url, total_timeout) from None
            # Do not attach exc_info: a transport exception may contain the
            # solved URL and its hidden verification values.
            logger.debug("Reddit bootstrap failed during transport")
            return False

    async def _try_reddit_bootstrap(
        self,
        url: str,
        deadline: float | None,
        total_timeout: float,
        observed_bootstrap_generation: int,
    ) -> int | None:
        """Deduplicate a bootstrap and return its client generation."""
        if reddit_solve_origin(url) is None:
            return None
        if deadline is None:
            await self._reddit_bootstrap_lock.acquire()
        else:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise WaferTimeout(url, total_timeout)
            try:
                await asyncio.wait_for(
                    self._reddit_bootstrap_lock.acquire(),
                    timeout=remaining,
                )
            except TimeoutError:
                raise WaferTimeout(url, total_timeout) from None
        try:
            if (
                self._reddit_bootstrap_generation > observed_bootstrap_generation
                and self._reddit_bootstrap_client_generation == self._client_generation
            ):
                return self._client_generation

            # A different coroutine may rotate the shared session while a
            # network leg is in flight. Retry on the replacement client under
            # the same overall deadline; never submit or replay cookies across
            # client generations.
            while True:
                client = self._client
                client_generation = self._client_generation
                solved = await self._reddit_bootstrap_on_client(
                    client,
                    client_generation,
                    url,
                    deadline,
                    total_timeout,
                )
                if solved is None:
                    self._reddit_subrequest_kwargs(url, deadline, total_timeout)
                    continue
                if not solved:
                    solved = await self._try_reddit_browser_bootstrap(
                        url,
                        deadline,
                    )
                    if not solved:
                        return None
                    client = self._client
                    client_generation = self._client_generation
                if self._reddit_client_changed(client, client_generation):
                    continue
                self._reddit_bootstrap_generation += 1
                self._reddit_bootstrap_client_generation = client_generation
                return client_generation
        finally:
            self._reddit_bootstrap_lock.release()

    async def _try_reddit_browser_bootstrap(
        self,
        url: str,
        deadline: float | None,
    ) -> bool:
        """Recover a failed inline bootstrap on Reddit's fixed HTML origin."""

        origin = reddit_solve_origin(url)
        if self._browser_solver is None or origin is None:
            return False
        # Deliberately do not pass the caller's max_response_size. This fixed
        # HTML root is internal challenge overhead and is never returned; the
        # cap still applies to the original response replayed through wreq.
        result = await self._try_browser_solve(
            ChallengeType.REDDIT,
            url,
            deadline,
            embedder=origin,
            use_solve_origin=False,
        )
        if not result:
            logger.debug("Reddit browser bootstrap failed")
            return False
        logger.info("Reddit anonymous cookies established in browser")
        return True

    async def _try_inline_solve(
        self,
        challenge: ChallengeType | None,
        body: str,
        url: str,
        deadline: float | None = None,
    ) -> bool:
        """Attempt inline challenge solving. Returns True if solved."""
        # Bound any solver sub-request (Amazon submit, TMD/Reddit bootstrap) by
        # the caller's remaining budget so a slow response can't overshoot the
        # overall timeout. ACW is pure computation -- no sub-request, no clamp.
        sub_timeout = None
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            sub_timeout = datetime.timedelta(seconds=remaining)
        if challenge == ChallengeType.ACW:
            cookie_value = solve_acw(body)
            if cookie_value:
                cookie_str = f"acw_sc__v2={cookie_value}; Path=/"
                self._record_cookie_scope(cookie_str, url)
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
                    sub_kw = {"timeout": sub_timeout} if sub_timeout is not None else {}
                    if target["method"] == "POST":
                        solve_resp = await self._client.post(
                            target["url"],
                            form=target["params"],
                            headers={"Referer": url},
                            **sub_kw,
                        )
                    else:
                        target_url = self._apply_params(target["url"], target["params"])
                        solve_resp = await self._client.get(
                            target_url,
                            headers={"Referer": url},
                            **sub_kw,
                        )
                    await self._cache_response_cookies(target["url"], solve_resp)
                    logger.info(
                        "Amazon captcha submitted inline",
                    )
                    return True
                except Exception:
                    logger.debug("Amazon inline solve failed")

        elif challenge == ChallengeType.TMD:
            homepage = tmd_homepage_url(url)
            try:
                homepage_resp = await self._client.get(
                    homepage,
                    **({"timeout": sub_timeout} if sub_timeout is not None else {}),
                )
                homepage_status = homepage_resp.status.as_int()
                homepage_headers = _decode_headers(homepage_resp.headers)
                homepage_content = await _aread_body_capped(homepage_resp, 1_000_000)
                homepage_body = homepage_content.decode(
                    resolve_charset(homepage_headers, homepage_content),
                    errors="replace",
                )
                homepage_challenge = detect_challenge(
                    homepage_status, homepage_headers, homepage_body
                )
                if 200 <= homepage_status < 300 and homepage_challenge is None:
                    await self._cache_response_cookies(homepage, homepage_resp)
                    logger.info("TMD session warmed")
                    return True
                logger.debug("TMD homepage remained challenged")
            except Exception:
                logger.debug("TMD homepage fetch failed")

        return False

    async def _arender_via_solver(
        self,
        url: str,
        timeout: float | None,
        max_size: int | None,
    ):
        """Await the solver's render, preferring its native async entry point."""

        async_render = getattr(self._browser_solver, "arender", None)
        render_callable = (
            async_render if callable(async_render) else self._browser_solver.render
        )
        kwargs = {"timeout": timeout}
        if max_size is not None and _callable_accepts_keyword(
            render_callable,
            "max_size",
        ):
            kwargs["max_size"] = max_size
        if callable(async_render):
            return await async_render(url, **kwargs)
        return await asyncio.to_thread(render_callable, url, **kwargs)

    async def _try_browser_solve(
        self,
        challenge: ChallengeType,
        url: str,
        deadline: float | None = None,
        embedder: str | None = None,
        replay: dict | None = None,
        max_size: int | None = None,
        use_solve_origin: bool = True,
        challenge_url: str | None = None,
        render: bool = False,
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
            render: navigate and capture the settled document instead of
                answering a challenge wafer already detected. The result is
                always a passthrough body; everything downstream (cookie
                scoping, persistence, jar injection, and the identity pin when
                the render had to solve an interstitial in place) is shared
                with the solve path.

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
            remaining = deadline - time.monotonic()
            solve_timeout = _browser_solve_timeout(remaining)
            if solve_timeout <= 0:
                logger.debug("No time budget left for browser solve")
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
        if use_solve_origin and self._solve_origin:
            embedder = self._solve_origin
        solve_kwargs = {
            "timeout": solve_timeout,
            "embedder": embedder,
            "replay": replay,
        }
        async_solve = getattr(self._browser_solver, "asolve", None)
        solve_callable = (
            async_solve if callable(async_solve) else self._browser_solver.solve
        )
        if max_size is not None and _callable_accepts_keyword(
            solve_callable,
            "max_size",
        ):
            solve_kwargs["max_size"] = max_size
        browser_attempts = 1
        if challenge is ChallengeType.TMD and deadline is not None:
            # Classify from the issued punishment URL when one is available:
            # ``challenge_url`` is extracted from the response body (MTop
            # answers an API call with the action already on the URL), and
            # falls back to ``url`` for a caller that requested a punishment
            # URL directly. A plain page navigation carries neither -- MTop
            # issues the action only after the browser navigates -- so that
            # case keeps the disposable-slider budget, which is correct for
            # the slider and merely not optimal for a reCAPTCHA punishment.
            browser_attempts = _tmd_browser_attempt_count(
                deadline - time.monotonic(),
                challenge_url or url,
            )
        result = None
        if render:
            result = await self._arender_via_solver(url, solve_timeout, max_size)
            browser_attempts = 0
        for browser_attempt in range(browser_attempts):
            if deadline is not None:
                if challenge is ChallengeType.TMD:
                    solve_timeout = _tmd_browser_attempt_timeout(
                        deadline - time.monotonic(),
                        browser_attempts - browser_attempt,
                    )
                else:
                    solve_timeout = _browser_attempt_timeout(
                        deadline - time.monotonic(),
                        browser_attempts - browser_attempt,
                    )
                if solve_timeout <= 0:
                    break
                solve_kwargs["timeout"] = solve_timeout
            if callable(async_solve):
                result = await async_solve(
                    url,
                    challenge.value,
                    **solve_kwargs,
                )
            else:
                result = await asyncio.to_thread(
                    solve_callable,
                    url,
                    challenge.value,
                    **solve_kwargs,
                )
            if result is not None:
                break
            if browser_attempt + 1 < browser_attempts:
                logger.info(
                    "TMD browser solve failed; retrying in a fresh context "
                    "(attempt %d/%d)",
                    browser_attempt + 2,
                    browser_attempts,
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
            c
            for c in result.cookies
            if browser_cookie_matches_host(c.get("domain", ""), domain)
        ]
        if challenge == ChallengeType.REDDIT and not reddit_has_cookie_evidence(
            {
                str(cookie.get("name", ""))
                for cookie in target_cookies
                if isinstance(cookie, dict)
            }
        ):
            logger.warning(
                "Reddit browser solve produced no authoritative cookie evidence"
            )
            return False
        if not target_cookies and result.response is None:
            logger.warning("Browser solve produced no cookies scoped to %s", reg)
            return False

        # Persist browser cookies to disk cache
        if self._cookie_cache and domain and target_cookies:
            cache_domain = (
                REDDIT_CACHE_DOMAIN
                if challenge == ChallengeType.REDDIT
                else domain
            )
            cache_entries = []
            for cookie in target_cookies:
                raw = format_cookie_str(cookie)
                expires = cookie.get("expires", -1)
                cache_entries.append(
                    {
                        "name": cookie["name"],
                        "raw": raw,
                        "url": url,
                        "domain": cookie.get("domain", domain),
                        "path": cookie.get("path", "/"),
                        "expires": (
                            time.time() + 86400 if expires <= 0 else float(expires)
                        ),
                        "last_used": time.time(),
                    }
                )
            try:
                await asyncio.to_thread(
                    self._cookie_cache.save,
                    cache_domain,
                    cache_entries,
                )
            except Exception:
                logger.debug("Failed to persist browser cookies")

        # Cache Kasada CT/ST tokens for per-request CD generation
        if result.extras and "ct" in result.extras:
            from wafer._kasada import store_session

            store_session(
                domain,
                ct=result.extras["ct"],
                st=result.extras.get("st", 0),
                cookies=target_cookies,
            )

        challenge_absent_passthrough = (
            getattr(result, "challenge_absent", False)
            and result.response is not None
        )

        # Align the replay identity to the browser that solved and pin it.
        # WAF clearance cookies are bound to the solving browser's TLS shape
        # AND its UA/client-hints (Cloudflare cf_clearance, DataDome), so wafer
        # pins the closest Chrome emulation (for the TLS shape) and replays the
        # browser's EXACT UA + sec-ch-ua version. Patchright's Chromium is often
        # newer than wreq's newest Emulation (e.g. Chrome 150 vs 149); adjacent
        # Chrome majors are wire-identical on JA4/H2, so this is coherent — and
        # required, or the freshly minted cookie is rejected on the first replay
        # and the session rotates away from the identity the cookie belongs to.
        # Skip Imperva (its token rides an unpinned wreq/native path — see
        # below), Reddit (its anonymous cookies are not UA-bound, and a
        # session-wide pin would disable the fallback rotation escape hatch),
        # and Safari (self._fingerprint is None; keep the Safari TLS).
        if (
            not challenge_absent_passthrough
            and self._fingerprint is not None
            and challenge
            not in (
                ChallengeType.IMPERVA,
                ChallengeType.REDDIT,
            )
        ):
            chrome_ver = chrome_version_from_ua(result.user_agent)
            if chrome_ver:
                full_ver = result.browser_version or chrome_full_version_from_ua(
                    result.user_agent
                )
                self._fingerprint.pin_to_browser(
                    result.user_agent, chrome_ver, full_ver
                )

        # A real solve changes the replay identity and needs a rebuilt client.
        # A challenge-absent passthrough earned no clearance identity: rebuilding
        # there would discard unrelated in-memory cookies. Merge its browser
        # cookies into the existing jar below instead.
        if not challenge_absent_passthrough:
            self._rebuild_client()

        # Also inject directly into jar (covers cache-disabled case)
        for cookie in target_cookies:
            try:
                raw = format_cookie_str(cookie)
                cookie_domain = cookie.get("domain")
                self._record_cookie_scope(
                    raw,
                    url,
                    domain=cookie_domain,
                    path=cookie.get("path"),
                    host_only=(
                        not bool(cookie_domain)
                        or not str(cookie_domain).startswith(".")
                    ),
                )
                self._client.cookie_jar.add(raw, url)
            except Exception as exc:
                logger.debug(
                    "Failed to inject cookie %s (%s)",
                    cookie.get("name", "?"),
                    type(exc).__name__,
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
            except Exception as exc:
                logger.debug("Failed to seed native-TLS jar (%s)", type(exc).__name__)

        # Passthrough: browser got real content without solving. TMD/Baxia is
        # different: Alibaba's post-slider page can be a small CSR shell while
        # the same cookies unlock the authoritative SSR response over wreq.
        # Always replay TMD through the normal transport instead of returning
        # that incomplete shell as successful content.
        if result.response is not None and challenge not in (
            ChallengeType.TMD,
            ChallengeType.REDDIT,
        ):
            body_bytes = result.response.body
            # Enforce the response-size cap on the browser body too (it never
            # went through the wreq capped-read path).
            if max_size is not None and len(body_bytes) > max_size:
                raise ResponseTooLarge(result.response.url, len(body_bytes), max_size)
            logger.info(
                "Browser passthrough challenge_type=%s (%d cookies injected, %d bytes)",
                challenge.value,
                len(target_cookies),
                len(body_bytes),
            )
            return WaferResponse(
                status_code=result.response.status,
                headers=result.response.headers,
                url=result.response.url,
                content=body_bytes,
                was_retried=True,
                emulation=self._serving_emulation_repr(),
                # Individual Set-Cookie values from the captured response
                # (the flat headers dict joins multi-value headers with
                # "; ", which is lossy for Set-Cookie). Mirrors native-TLS.
                raw_set_cookie=getattr(result.response, "set_cookie", None) or None,
            )

        logger.info(
            "Browser solved challenge_type=%s (cookie_count=%d)",
            challenge.value,
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
            status, hdrs, body_bytes, final_url, *rest = await asyncio.to_thread(
                transport.request,
                method,
                url,
                headers,
                body,
                timeout,
                max_size,
            )
        except (ResponseTooLarge, TooManyRedirects, WaferTimeout):
            # Hard limits (size cap, redirect loop, total-budget timeout),
            # not transport hiccups: propagate rather than swallowing into a
            # None (which would fall back to the wreq path and silently
            # bypass the limit). The native per-hop timeout IS the remaining
            # total budget, so a WaferTimeout here means the deadline is
            # spent -- surfacing it matches the wreq-path rule (hang past
            # the deadline -> WaferTimeout, never ConnectionFailed).
            raise
        except Exception as exc:
            logger.warning("Native-TLS request failed (%s)", type(exc).__name__)
            return None
        return self._native_make_response(
            status,
            hdrs,
            body_bytes,
            final_url,
            start_time,
            state,
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

    async def browser_prime(
        self,
        url: str,
        *,
        timeout: float | datetime.timedelta | None = None,
        max_response_size: int | None = None,
    ) -> bool:
        """Deliberately visit an origin in the configured browser solver.

        This is for API-level bot rejections delivered as ordinary JSON, where
        automatic HTML challenge detection cannot trigger. Browser cookies are
        imported, scoped, persisted, and fingerprint-pinned through the same
        path as a detected challenge. The caller must still retry and validate
        its application response; ``True`` only means browser state was earned.
        """

        if self._browser_solver is None:
            return False
        timeout_secs = (
            timeout.total_seconds()
            if hasattr(timeout, "total_seconds")
            else float(timeout)
            if timeout is not None
            else self.timeout.total_seconds()
        )
        if timeout_secs <= 0:
            return False
        effective_max_size = (
            self.max_response_size if max_response_size is None else max_response_size
        )
        result = await self._try_browser_solve(
            ChallengeType.GENERIC_JS,
            url,
            time.monotonic() + timeout_secs,
            max_size=effective_max_size,
        )
        # A passthrough response can be useful to ``request()``, but it does
        # not prove browser state was earned.  ``browser_prime`` promises the
        # latter specifically, so never report success without imported
        # target-domain cookies.
        return result is True

    async def browser_solve_challenge(
        self,
        url: str,
        challenge_type: str,
        *,
        timeout: float | datetime.timedelta | None = None,
        max_response_size: int | None = None,
    ) -> bool:
        """Solve an already-issued browser challenge and import its state.

        Unlike :meth:`browser_prime`, this intentionally navigates ``url``
        itself.  It is for a challenge URL returned by an application API
        (for example AliExpress MTop's one-time TMD punishment URL), where a
        session-level ``solve_origin`` would bypass the actual widget.
        ``True`` means wafer verified the browser solver's authoritative
        completion and imported the target-domain cookies; callers must still
        retry and validate their application response.
        """

        try:
            challenge = ChallengeType(challenge_type)
        except ValueError:
            return False
        if self._browser_solver is None:
            return False
        timeout_secs = (
            timeout.total_seconds()
            if hasattr(timeout, "total_seconds")
            else float(timeout)
            if timeout is not None
            else self.timeout.total_seconds()
        )
        if timeout_secs <= 0:
            return False
        effective_max_size = (
            self.max_response_size if max_response_size is None else max_response_size
        )
        result = await self._try_browser_solve(
            challenge,
            url,
            time.monotonic() + timeout_secs,
            max_size=effective_max_size,
            use_solve_origin=False,
        )
        return result is True

    async def render(
        self,
        url: str,
        *,
        timeout: float | datetime.timedelta | None = None,
        max_response_size: int | None = None,
    ) -> WaferResponse:
        """Fetch ``url`` by rendering it in a real browser.

        Async counterpart to :meth:`SyncSession.render`. When a page writes
        its own content with client-side JavaScript the server ships a shell,
        and no fingerprint recovers what was never in the bytes. This
        navigates the browser solver to ``url``, waits for rendering to
        settle, and returns the resulting document.

        The browser follows redirects regardless of ``follow_redirects``, so
        ``WaferResponse.url`` is the final URL and ``history`` is empty.
        Cookies the page set are merged into the session jar, so a following
        :meth:`get` reuses them.

        A non-HTML resource (JSON, XML, an image) comes back as the bytes the
        server sent under its real content type, so :meth:`WaferResponse.json`
        works on a rendered API URL; Chrome would otherwise wrap those in a
        viewer document and the serialized DOM would be that wrapper.

        An interstitial is solved in place with the same per-WAF handlers the
        transport path uses, and the session then pins its replay identity to
        the solving browser so the earned clearance survives the next request.

        A session with no ``browser_solver=`` creates one on the first render
        and closes it on exit; from then on the session can also browser-solve
        challenges on ordinary requests.

        Raises ``ChallengeDetected`` if the document is still a WAF challenge
        after that attempt, and ``ConnectionFailed`` if the browser produced
        no document within the timeout.
        """

        self._ensure_browser_solver()
        start_time = time.monotonic()
        timeout_secs = (
            timeout.total_seconds()
            if hasattr(timeout, "total_seconds")
            else float(timeout)
            if timeout is not None
            else self.timeout.total_seconds()
        )
        if timeout_secs <= 0:
            raise WaferTimeout(url, timeout_secs)
        effective_max_size = (
            self.max_response_size if max_response_size is None else max_response_size
        )
        result = await self._try_browser_solve(
            ChallengeType.GENERIC_JS,
            url,
            start_time + timeout_secs,
            max_size=effective_max_size,
            use_solve_origin=False,
            render=True,
        )
        if not isinstance(result, WaferResponse):
            raise ConnectionFailed(url, "browser render produced no document")
        result.elapsed = time.monotonic() - start_time
        # Classify the rendered body exactly like a transport response: a
        # WAF interstitial that outlived the render is a challenge, not
        # content, and the caller must be able to tell the two apart.
        challenge = detect_challenge(
            result.status_code,
            result.headers,
            result.text,
        )
        if challenge is not None:
            result.challenge_type = challenge.value
            raise ChallengeDetected(
                challenge.value,
                url,
                result.status_code,
                response=result,
            )
        return result

    async def request(self, method: str, url: str, **kwargs) -> WaferResponse:
        """Send an HTTP request with retry, backoff, and challenge handling."""
        start_time = time.monotonic()

        # Extract per-request overrides (popped once, reused)
        extra_headers = kwargs.pop("headers", None)
        params = kwargs.pop("params", None)
        req_timeout = kwargs.pop("timeout", None)
        req_attempt_timeout = kwargs.pop("attempt_timeout", None)
        # Per-request response-size cap overrides the session value.
        max_response_size = kwargs.pop("max_response_size", self.max_response_size)
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
                await self._rate_limiter.wait_async(
                    domain,
                    max_wait=(
                        deadline - time.monotonic() if deadline is not None else None
                    ),
                )
            logger.debug(
                "%s host=%s (Opera Mini)",
                method,
                extract_domain(url) or "unknown",
            )
            # Single request, no retries -- bound it by the remaining total
            # budget (the rate-limit wait above may have eaten some of it).
            timeout = deadline - time.monotonic()
            if timeout <= 0:
                raise WaferTimeout(url, timeout_secs)
            loop = asyncio.get_event_loop()
            (
                status,
                resp_headers,
                body_bytes,
                final_url,
                set_cookies,
            ) = await loop.run_in_executor(
                None,
                lambda: self._om_identity.request(
                    url,
                    headers=extra_headers,
                    timeout=timeout,
                    max_size=max_response_size,
                ),
            )
            if self._rate_limiter:
                self._rate_limiter.record(domain)
            return WaferResponse(
                status_code=status,
                content=body_bytes,
                text=None,
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
        reddit_bootstrap_attempted = False
        tmd_inline_attempted = False
        observed_reddit_bootstrap_generation = self._reddit_bootstrap_generation
        reddit_replay_client_generation: int | None = None
        native_attempted = False
        native_retries = 0
        redirects_followed = 0
        history: list[HistoryEntry] = []

        logger.debug("%s host=%s", method, extract_domain(url) or "unknown")

        while True:
            # Per-request deadline: abort retry loop if exceeded
            if deadline is not None and time.monotonic() > deadline:
                raise WaferTimeout(url, timeout_secs)

            # Rate limiting: wait if too soon since last request to this domain
            if self._rate_limiter:
                await self._rate_limiter.wait_async(
                    domain,
                    max_wait=(
                        deadline - time.monotonic() if deadline is not None else None
                    ),
                )

            # Sticky native-TLS: this host was proven to need OpenSSL
            # (Imperva fingerprints wreq's BoringSSL stack and challenges it
            # even with valid cookies). Route straight through urllib — and
            # the native jar, not wreq's, holds the WAF cookies.
            if domain in self._native_tls_domains:
                native_resp = await self._try_native_tls(
                    method,
                    current_url,
                    extra_headers,
                    kwargs,
                    deadline,
                    start_time,
                    state,
                    max_response_size,
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
                        native_retries,
                        NATIVE_MAX_RETRIES,
                        current_url,
                        delay,
                    )
                    await asyncio.sleep(self._clamp_delay(delay, deadline))
                    continue
                if native_resp is None:
                    raise ConnectionFailed(current_url, "native-TLS request failed")
                # Native retries exhausted on a persistent reese84 challenge
                # (the heavy state where even OpenSSL must present a token).
                # If a browser is available, un-pin and fall back to the wreq
                # path: it escalates to the browser solve, which earns a
                # reese84 token that wreq then carries through. Without a
                # browser there's no way to mint the token, so surface it.
                if self._browser_solver is not None:
                    logger.info(
                        "Native-TLS exhausted; reverting to wreq + browser solve",
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
                        native_resp.challenge_type or ChallengeType.IMPERVA.value,
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
                kwargs["timeout"] = datetime.timedelta(seconds=attempt_limit)

            # Make the request. When a resolve pin is set, canonicalize the
            # URL host (lowercase + trailing-dot strip) so wreq's DnsOptions -
            # which matches its map against the URL host verbatim - can't miss
            # the pin on a mixed-case/trailing-dot host and fall through to
            # real DNS (the SSRF-rebinding hole). No-op when unpinned.
            wreq_url = (
                _canonicalize_url_host(current_url) if self._resolve else current_url
            )
            if (
                reddit_replay_client_generation is not None
                and self._client_generation != reddit_replay_client_generation
            ):
                # A concurrent rotation replaced the solved client before
                # replay. Do not send mismatched cookies; let this request
                # detect the gate on the new client and bootstrap it once.
                reddit_replay_client_generation = None
                reddit_bootstrap_attempted = False
                continue
            request_client = self._client
            reddit_replay_client_generation = None
            try:
                resp = await request_client.request(m, wreq_url, **kwargs)
            except Exception as e:
                # Every attempt now carries a timeout kwarg -- attempt_timeout
                # if set, else the remaining-budget clamp -- so any wreq
                # TimeoutError stems from OUR deadline, not the network. Treat
                # it as retryable (the per-attempt cap exists precisely so
                # retries/rotations fire instead of one hung attempt eating the
                # whole budget) and, when finally giving up, surface it as a
                # WaferTimeout rather than a bare ConnectionFailed. The loop-top
                # deadline check still bounds the total time.
                attempt_timed_out = isinstance(e, wreq.exceptions.TimeoutError)
                # The wall-clock limit this attempt actually ran under (for
                # logging); attempt_limit is the min(cap, remaining) bound.
                timed_out_after = (
                    attempt_limit if attempt_limit is not None else timeout_secs
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
                                timed_out_after,
                                delay,
                            )
                            await asyncio.sleep(self._clamp_delay(delay, deadline))
                            continue
                        pinned = (
                            self._fingerprint is not None and self._fingerprint.pinned
                        )
                        # Mirror the 403 path: clear cookies (unless pinned)
                        # and advance the cross-family ladder / fingerprint_pool
                        # rather than only cycling Chrome versions. Going
                        # through _advance_rotation keeps self.headers coherent
                        # with the TLS identity for non-Chrome sessions.
                        if self._cookie_cache and not pinned:
                            await asyncio.to_thread(self._clear_cached_cookies, domain)
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
                            timed_out_after,
                            state.rotation_retries,
                            state.max_rotations,
                            delay,
                        )
                        await asyncio.sleep(self._clamp_delay(delay, deadline))
                        continue
                    if attempt_timed_out:
                        # Report the attempt cap only when IT -- not the total
                        # deadline -- was the binding limit and no explicit
                        # per-request total was given; otherwise the total
                        # budget is the headline. attempt_limit == attempt_secs
                        # means the cap (not the deadline) bounded this try.
                        attempt_cap_bound = (
                            attempt_secs is not None
                            and attempt_limit is not None
                            and attempt_limit == attempt_secs
                        )
                        raise WaferTimeout(
                            current_url,
                            attempt_secs
                            if (req_timeout is None and attempt_cap_bound)
                            else timeout_secs,
                        ) from e
                    raise ConnectionFailed(
                        current_url,
                        _connection_failure_reason(current_url, e),
                    ) from e
                state.use_retry()
                delay = calculate_backoff(state.normal_retries - 1)
                if deadline is not None:
                    delay = min(delay, max(0.0, deadline - time.monotonic()))
                logger.debug(
                    "Connection error, retry %d/%d in %.1fs: %s",
                    state.normal_retries,
                    state.max_retries,
                    delay,
                    e,
                )
                await asyncio.sleep(self._clamp_delay(delay, deadline))
                continue

            status = resp.status.as_int()
            self._record_response_cookie_scopes(current_url, resp)

            # Record request timestamp for rate limiting
            if self._rate_limiter:
                self._rate_limiter.record(domain)

            # 3xx → follow redirect
            if self.follow_redirects and 300 <= status < 400 and status != 304:
                location = _extract_location(resp.headers)
                if location:
                    if redirects_followed >= self.max_redirects:
                        raise TooManyRedirects(current_url, self.max_redirects)
                    new_url = self._resolve_redirect_url(current_url, location)
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
                    cross_origin = self._is_cross_origin(current_url, new_url)
                    current_url = new_url
                    domain = extract_domain(current_url) or current_url
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
            content_type = headers.get("content-type", "")
            reddit_response = reddit_solve_origin(current_url) is not None
            reddit_gate_probe = (
                max_response_size is not None
                and status in (200, 403)
                and reddit_response
                and _is_challengeable_content_type(content_type)
            )
            body_read_cap = max_response_size
            if reddit_gate_probe:
                body_read_cap = max(
                    max_response_size,
                    (
                        REDDIT_GATE_MAX_BYTES
                        if status == 403
                        else REDDIT_VERIFICATION_MAX_BYTES
                    ),
                )

            # Response-size cap: short-circuit on a declared Content-Length
            # over the cap before reading the body at all.
            if body_read_cap is not None:
                declared = _content_length_over_cap(resp, body_read_cap)
                if declared is not None:
                    raise ResponseTooLarge(current_url, declared, max_response_size)

            # Read body: wreq's bytes() returns the DECOMPRESSED body
            # (gzip/br/zstd already handled), so raw_content is the true
            # byte stream. Text content is decoded charset-aware (header
            # charset -> <meta charset> sniff -> UTF-8) -- the same
            # resolution WaferResponse.text uses -- instead of wreq's
            # text(), which never meta-sniffs.
            is_binary = _is_binary_content_type(headers.get("content-type", ""))
            try:
                if body_read_cap is not None:
                    # Streamed early-abort: stop the moment the running total
                    # passes the cap, never buffering the whole oversize body.
                    raw_content = await _aread_body_capped(resp, body_read_cap)
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
                    raise ConnectionFailed(current_url, f"body decode: {e}") from e
                state.use_retry()
                delay = calculate_backoff(state.normal_retries - 1)
                logger.debug(
                    "Body decode error, retry %d/%d in %.1fs: %s",
                    state.normal_retries,
                    state.max_retries,
                    delay,
                    e,
                )
                await asyncio.sleep(self._clamp_delay(delay, deadline))
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
                    status,
                    state.normal_retries,
                    state.max_retries,
                    delay,
                )
                await asyncio.sleep(self._clamp_delay(delay, deadline))
                continue

            # Challenge detection (HTML responses only — WAF challenges
            # are always HTML pages). Skip for:
            # - Binary content (images, PDFs, etc.)
            # - Non-HTML text (JSON, XML) — API endpoints may have
            #   challenge markers in cookies/headers but browser-solving
            #   the API URL itself can't work (renders raw JSON).
            # - Opera Mini / Dart -- non-browser profiles.
            challenge = (
                detect_challenge(status, headers, body)
                if body is not None
                and self._profile not in (Profile.OPERA_MINI, Profile.DART)
                and _is_challengeable_content_type(content_type)
                else None
            )
            if challenge == ChallengeType.REDDIT and not reddit_response:
                challenge = None
            if (
                max_response_size is not None
                and len(raw_content) > max_response_size
                and not (challenge == ChallengeType.REDDIT and reddit_response)
            ):
                raise ResponseTooLarge(
                    current_url,
                    len(raw_content),
                    max_response_size,
                )

            # Terminal WAF block: report it before touching the retry,
            # rotation, or session-health budget. Every one of those would
            # buy another identical denial, and retiring the session would
            # throw away state that was never the reason for the block.
            if challenge is not None and challenge in TERMINAL_CHALLENGES:
                blocked = self._make_response(
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
                if self.max_rotations == 0:
                    return blocked
                raise RequestBlocked(
                    challenge.value,
                    current_url,
                    status,
                    response=blocked,
                )

            # 429 without detected challenge → rate limit retry
            if status == 429 and challenge is None:
                retry_after = parse_retry_after(headers.get("retry-after", ""))
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
                    pinned = self._fingerprint is not None and self._fingerprint.pinned
                    if self._cookie_cache and not pinned:
                        await asyncio.to_thread(self._clear_cached_cookies, domain)
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
                    delay,
                    state.rotation_retries,
                    state.max_rotations,
                )
                await asyncio.sleep(self._clamp_delay(delay, deadline))
                continue

            # Challenge or bare 403 → try inline solver, then rotate
            if challenge is not None or (status == 403 and body is not None):
                # Session health: track failure (defer retirement
                # until after budget check to avoid destroying
                # state before raising)
                should_retire = self._record_failure(domain)

                # Reddit's gate response establishes half of the anonymous
                # cookie set (csv/edgebucket); persist that leg alongside the
                # verification cookies so cache_dir survives a process restart.
                if challenge == ChallengeType.REDDIT and not reddit_bootstrap_attempted:
                    await self._cache_response_cookies(
                        current_url,
                        resp,
                        cache_domain=REDDIT_CACHE_DOMAIN,
                    )

                # Try inline solver first (no fingerprint rotation,
                # does NOT consume rotation budget — separate cap). Reddit
                # gets exactly one bootstrap + replay; repeating the same
                # navigation cannot improve a failed bootstrap.
                inline_allowed = (
                    challenge != ChallengeType.REDDIT or not reddit_bootstrap_attempted
                ) and (challenge != ChallengeType.TMD or not tmd_inline_attempted)
                if challenge == ChallengeType.REDDIT:
                    reddit_bootstrap_attempted = True
                elif challenge == ChallengeType.TMD:
                    tmd_inline_attempted = True
                inline_solved = False
                solved_client_generation = None
                if (
                    challenge == ChallengeType.REDDIT
                    and inline_allowed
                    and state.inline_solves < state.max_inline_solves
                ):
                    solved_client_generation = await self._try_reddit_bootstrap(
                        current_url,
                        deadline,
                        timeout_secs,
                        observed_reddit_bootstrap_generation,
                    )
                    inline_solved = solved_client_generation is not None
                elif (
                    challenge is not None
                    and inline_allowed
                    and state.inline_solves < state.max_inline_solves
                ):
                    inline_solved = await self._try_inline_solve(
                        challenge, body, current_url, deadline
                    )
                if challenge is not None and inline_solved:
                    state.inline_solves += 1
                    if solved_client_generation is not None:
                        reddit_replay_client_generation = solved_client_generation
                    delay = calculate_backoff(
                        state.inline_solves - 1,
                        base=0.5,
                        max_delay=10.0,
                    )
                    logger.debug(
                        "%s solved inline (%d/%d), retrying in %.1fs",
                        challenge.value,
                        state.inline_solves,
                        state.max_inline_solves,
                        delay,
                    )
                    await asyncio.sleep(self._clamp_delay(delay, deadline))
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
                        method,
                        current_url,
                        extra_headers,
                        kwargs,
                        deadline,
                        start_time,
                        state,
                        max_response_size,
                    )
                    if native_resp is not None:
                        native_resp.history = history
                    # A non-challenge reply means the OpenSSL client got past
                    # the WAF — pin the host regardless of HTTP status (a real
                    # 404/500 from the origin still proves the bypass works).
                    if native_resp is not None and native_resp.challenge_type is None:
                        self._native_tls_domains.add(domain)
                        if self._rate_limiter:
                            self._rate_limiter.record(domain)
                        self._record_success(domain)
                        self._record_url(current_url)
                        logger.info(
                            "Imperva bypassed via native-TLS (host pinned)",
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
                        challenge,
                        current_url,
                        deadline,
                        embedder=self._imperva_embedder(
                            challenge, current_url, extra_headers, kwargs
                        ),
                        replay=self._browser_replay(method, kwargs),
                        max_size=max_response_size,
                        challenge_url=(
                            _tmd_punish_url_from_body(body, current_url)
                            if challenge is ChallengeType.TMD
                            else None
                        ),
                    )
                    if isinstance(browser_result, WaferResponse):
                        self._record_success(domain)
                        self._record_url(current_url)
                        browser_result.elapsed = time.monotonic() - start_time
                        browser_result.history = history
                        return browser_result
                    if browser_result:
                        # Browser solved and injected cookies — reset
                        # failure counter so the retry starts clean.
                        self._record_success(domain)
                        continue

                # No browser solver — rotation can't help JS-only challenges
                if self._browser_solver is None and challenge in JS_ONLY_CHALLENGES:
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
                        and challenge != ChallengeType.REDDIT
                        and browser_attempted_type != challenge.value
                        and self._browser_solver is not None
                    ):
                        browser_attempted_type = challenge.value
                        browser_result = await self._try_browser_solve(
                            challenge,
                            current_url,
                            deadline,
                            embedder=self._imperva_embedder(
                                challenge,
                                current_url,
                                extra_headers,
                                kwargs,
                            ),
                            replay=self._browser_replay(method, kwargs),
                            max_size=max_response_size,
                        )
                        if isinstance(browser_result, WaferResponse):
                            self._record_success(domain)
                            self._record_url(current_url)
                            browser_result.elapsed = time.monotonic() - start_time
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
                    pinned = self._fingerprint is not None and self._fingerprint.pinned
                    if self._cookie_cache and not pinned:
                        await asyncio.to_thread(self._clear_cached_cookies, domain)
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
                    "%s at %s, rotated (rotation %d/%d), waiting %.1fs",
                    challenge.value if challenge else "403",
                    current_url,
                    state.rotation_retries,
                    self.max_rotations,
                    delay,
                )
                await asyncio.sleep(self._clamp_delay(delay, deadline))
                continue

            # 200 with empty text body → normal retry (skip for binary)
            if body is not None and status == 200 and not body.strip():
                if not state.can_retry:
                    # max_retries=0 or max_rotations=0 (.bulk()): the
                    # documented contract is to RETURN the empty-200 response,
                    # never to rotate — matching the 429/challenge no-rotation
                    # gates. This must be checked BEFORE the 200-capable
                    # rotation branch below, which would otherwise rotate a
                    # max_retries=0 caller that still has rotation budget.
                    if self.max_retries == 0 or self.max_rotations == 0:
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
                    if domain in self._body_capable_domains and state.can_rotate:
                        state.use_rotation()
                        pinned = (
                            self._fingerprint is not None and self._fingerprint.pinned
                        )
                        if self._cookie_cache and not pinned:
                            await asyncio.to_thread(self._clear_cached_cookies, domain)
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
                        await asyncio.sleep(self._clamp_delay(delay, deadline))
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
                    state.normal_retries,
                    state.max_retries,
                    delay,
                )
                await asyncio.sleep(self._clamp_delay(delay, deadline))
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
        self._record_cookie_scope(raw_set_cookie, url)
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
            scraped = await _recaptcha_v3._scrape_v_async(self.request, enterprise)
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
                logger.debug("BrowserSolver.close() failed")
