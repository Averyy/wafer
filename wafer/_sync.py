"""SyncSession -- synchronous HTTP client wrapping rnet.blocking.Client."""

import datetime
import logging
import time

import rnet.blocking
from rnet import Method

from wafer._base import (
    BaseSession,
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
from wafer._cookies import extract_domain
from wafer._errors import (
    ChallengeDetected,
    ConnectionFailed,
    EmptyResponse,
    RateLimited,
    TooManyRedirects,
    WaferTimeout,
)
from wafer._fingerprint import chrome_version_from_ua, emulation_for_version
from wafer._profiles import Profile
from wafer._response import WaferResponse
from wafer._retry import RetryState, calculate_backoff, parse_retry_after
from wafer._solvers import (
    parse_amazon_captcha,
    solve_acw,
    tmd_homepage_url,
)

logger = logging.getLogger("wafer")


class SyncSession(BaseSession):
    """Synchronous HTTP session with anti-detection defaults.

    Not thread-safe - use one instance per thread.
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if self._profile is Profile.OPERA_MINI:
            self._client = None  # Opera Mini bypasses rnet entirely
        else:
            self._client = rnet.blocking.Client(
                **self._build_client_kwargs()
            )
            self._hydrate_jar_from_cache()

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

    def _cache_response_cookies(self, url: str, resp) -> None:
        """Write-through: save Set-Cookie headers to disk cache."""
        if self._cookie_cache is None:
            return
        try:
            domain = extract_domain(url)
            if not domain:
                return
            raw_cookies = resp.headers.get_all("set-cookie")
            if raw_cookies:
                self._cookie_cache.save_from_headers(
                    domain, raw_cookies, url
                )
        except Exception:
            logger.debug(
                "Failed to cache cookies for %s",
                url,
                exc_info=True,
            )

    def _rebuild_client(self) -> None:
        """Rebuild the rnet client with a fresh TLS session and cookie jar.

        Creates a new rnet.blocking.Client, discarding the old client's connection
        pool, TLS session tickets, and in-memory cookie jar. Only cookies
        persisted to disk cache (via _cache_response_cookies or browser
        solve) survive the rebuild; normal HTTP response cookies that were
        only in the in-memory jar are intentionally lost.

        This is correct for rotation/retirement: cookies are bound to the
        TLS fingerprint that earned them, and replaying them on a different
        fingerprint can trigger WAF flags. For rotate_every (unlinkable
        request sequences), cookie loss is the desired isolation property.
        """
        self._client = rnet.blocking.Client(**self._build_client_kwargs())
        self._hydrate_jar_from_cache()
        logger.debug(
            "Client rebuilt with emulation=%s", self.emulation
        )

    def _retire_session(self, domain: str) -> None:
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
            self._cookie_cache.clear(domain)
        self._client = rnet.blocking.Client(**self._build_client_kwargs())
        self._hydrate_jar_from_cache()
        self._domain_failures.pop(domain, None)
        logger.warning(
            "Session retired for %s: emulation=%s",
            domain,
            self.emulation,
        )

    def _try_inline_solve(
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
                        self._cookie_cache.save(
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
                        solve_resp = self._client.post(
                            target["url"],
                            form=target["params"],
                            headers={"Referer": url},
                        )
                    else:
                        solve_resp = self._client.get(
                            target["url"],
                            params=target["params"] or None,
                            headers={"Referer": url},
                        )
                    self._cache_response_cookies(
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
                homepage_resp = self._client.get(homepage)
                self._cache_response_cookies(homepage, homepage_resp)
                logger.info("TMD session warmed via %s", homepage)
                return True
            except Exception:
                logger.debug(
                    "TMD homepage fetch failed", exc_info=True
                )

        return False

    def _try_browser_solve(
        self, challenge: ChallengeType, url: str
    ) -> WaferResponse | bool:
        """Attempt browser-based challenge solving.

        Returns:
            WaferResponse: browser got real content without challenge
                (passthrough - caller should return this directly).
            True: challenge solved, cookies injected - caller should
                retry the TLS request.
            False: browser solve failed.
        """
        from wafer.browser import format_cookie_str

        result = self._browser_solver.solve(url, challenge.value)
        if result is None:
            return False

        domain = extract_domain(url) or ""

        # Filter cookies to target domain only (browser context
        # returns cookies for all domains including CDN/challenge
        # subdomains like challenges.cloudflare.com)
        target_cookies = [
            c for c in result.cookies
            if domain and c.get("domain", "").lstrip(".").endswith(
                domain.lstrip("www.")
            )
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
                            0.0 if expires < 0 else float(expires)
                        ),
                        "last_used": time.time(),
                    }
                )
            self._cookie_cache.save(domain, cache_entries)

        # Cache Kasada CT/ST tokens for per-request CD generation
        if result.extras and "ct" in result.extras:
            from wafer._kasada import store_session
            store_session(
                domain,
                ct=result.extras["ct"],
                st=result.extras.get("st", 0),
                cookies=target_cookies,
            )

        # Match emulation to browser's Chrome version.
        # Skip for Safari — keep Safari TLS identity after browser solve.
        if self._fingerprint is not None:
            chrome_ver = chrome_version_from_ua(result.user_agent)
            if chrome_ver:
                em = emulation_for_version(chrome_ver)
                if em:
                    self._fingerprint.reset(em)

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

        # Passthrough: browser got real content without solving
        if result.response is not None:
            logger.info(
                "Browser passthrough %s at %s "
                "(%d cookies injected, %d bytes)",
                challenge.value,
                url,
                len(target_cookies),
                len(result.response.body),
            )
            text = result.response.body.decode(
                "utf-8", errors="replace"
            )
            return WaferResponse(
                status_code=result.response.status,
                headers=result.response.headers,
                url=result.response.url,
                content=result.response.body,
                text=text,
                was_retried=True,
            )

        logger.info(
            "Browser solved %s at %s (%d cookies injected)",
            challenge.value,
            url,
            len(target_cookies),
        )
        return True

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
            elapsed=time.monotonic() - start_time,
            was_retried=was_retried,
            retries=state.normal_retries if state else 0,
            rotations=state.rotation_retries if state else 0,
            inline_solves=state.inline_solves if state else 0,
            challenge_type=challenge_type,
            raw=raw,
        )

    def request(self, method: str, url: str, **kwargs) -> WaferResponse:
        """Send an HTTP request with retry, backoff, and challenge handling."""
        start_time = time.monotonic()

        # Extract per-request overrides (popped once, reused)
        extra_headers = kwargs.pop("headers", None)
        params = kwargs.pop("params", None)
        req_timeout = kwargs.pop("timeout", None)
        if params:
            url = self._apply_params(url, params)

        # Per-request timeout → overall deadline for retry loop
        if req_timeout is not None:
            timeout_secs = (
                req_timeout.total_seconds()
                if hasattr(req_timeout, "total_seconds")
                else float(req_timeout)
            )
            deadline = start_time + timeout_secs
        else:
            timeout_secs = self.timeout.total_seconds()
            deadline = None  # no per-request deadline

        # Opera Mini: bypass rnet entirely, use stdlib urllib (OpenSSL).
        # No challenge detection, no fingerprint rotation, no retries.
        # Opera Mini is a no-JS proxy browser — only GET navigations.
        if self._profile is Profile.OPERA_MINI:
            if method.upper() != "GET":
                raise ValueError(
                    f"Opera Mini profile only supports GET, got {method!r}"
                )
            domain = extract_domain(url) or url
            if self._rate_limiter:
                self._rate_limiter.wait_sync(domain)
            logger.debug("%s %s (Opera Mini)", method, url)
            timeout = timeout_secs
            status, resp_headers, text, final_url = self._om_identity.request(
                url, headers=extra_headers, timeout=timeout,
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
                raw=None,
            )

        state = RetryState(self.max_retries, self.max_rotations)
        m = _to_method(method) if isinstance(method, str) else method
        domain = extract_domain(url) or url
        current_url = url

        browser_attempted = False
        redirects_followed = 0

        logger.debug("%s %s", method, url)

        while True:
            # Per-request deadline: abort retry loop if exceeded
            if deadline is not None and time.monotonic() > deadline:
                raise WaferTimeout(url, timeout_secs)

            # Rate limiting: wait if too soon since last request to this domain
            if self._rate_limiter:
                self._rate_limiter.wait_sync(domain)

            # TLS session rotation for unlinkable requests
            if self._rotate_every:
                self._request_count += 1
                if self._request_count % self._rotate_every == 0:
                    self._rebuild_client()

            # Rebuild merged headers each iteration (fingerprint may rotate)
            kwargs["headers"] = self._build_headers(
                current_url, extra_headers, method=method
            )

            # Clamp per-attempt timeout to remaining deadline so a
            # single slow response can't overshoot the user's budget.
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise WaferTimeout(url, timeout_secs)
                kwargs["timeout"] = datetime.timedelta(
                    seconds=min(timeout_secs, remaining)
                )

            # Make the request
            try:
                resp = self._client.request(m, current_url, **kwargs)
            except Exception as e:
                if not state.can_retry:
                    raise ConnectionFailed(current_url, str(e)) from e
                state.use_retry()
                delay = calculate_backoff(state.normal_retries - 1)
                logger.debug(
                    "Connection error, retry %d/%d in %.1fs: %s",
                    state.normal_retries, state.max_retries, delay, e,
                )
                time.sleep(delay)
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
                    domain = extract_domain(current_url) or current_url
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
                or browser_attempted
            )

            # Read body: bytes for binary content, text for text
            is_binary = _is_binary_content_type(
                headers.get("content-type", "")
            )
            try:
                if is_binary:
                    raw_content = resp.bytes()
                    body = None
                else:
                    body = resp.text()
                    raw_content = body.encode("utf-8")
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
                time.sleep(delay)
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
                        raw=resp,
                    )
                state.use_retry()
                delay = calculate_backoff(state.normal_retries - 1)
                logger.debug(
                    "%d server error, retry %d/%d in %.1fs",
                    status, state.normal_retries, state.max_retries, delay,
                )
                time.sleep(delay)
                continue

            # Challenge detection (HTML responses only — WAF challenges
            # are always HTML pages). Skip for:
            # - Binary content (images, PDFs, etc.)
            # - Non-HTML text (JSON, XML) — API endpoints may have
            #   challenge markers in cookies/headers but browser-solving
            #   the API URL itself can't work (renders raw JSON).
            # - Opera Mini — can't solve challenges.
            content_type = headers.get("content-type", "")
            challenge = (
                detect_challenge(status, headers, body)
                if body is not None
                and self._profile is not Profile.OPERA_MINI
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
                            raw=resp,
                        )
                    raise RateLimited(current_url, retry_after)

                # Session health: track failure (only retire if
                # we still have budget — avoids destroying state
                # right before raising)
                retired = self._record_failure(domain)
                if retired:
                    self._retire_session(domain)

                state.use_rotation()
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
                time.sleep(delay)
                if not retired:
                    # Clear domain cookies on every rotation - stale
                    # cookies from a different TLS identity cause WAF
                    # re-challenges (cf_clearance, _abck are TLS-bound).
                    if self._cookie_cache:
                        self._cookie_cache.clear(domain)
                    if state.rotation_retries == 1:
                        pass  # first rotation: just fresh TLS + cleared cookies
                    elif (
                        self._fingerprint is not None
                        and not self._tried_safari
                    ):
                        self._switch_to_safari()
                    elif (
                        self._safari_identity is not None
                        and self._profile is not Profile.SAFARI
                    ):
                        self._switch_to_chrome()
                    elif self._fingerprint is not None:
                        self._fingerprint.rotate()
                    self._rebuild_client()
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
                    and self._try_inline_solve(
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
                    time.sleep(delay)
                    continue

                # Early browser solve for JS-only challenges (rotation
                # can't help — these require JS execution)
                if (
                    not browser_attempted
                    and self._browser_solver is not None
                    and challenge in JS_ONLY_CHALLENGES
                ):
                    browser_attempted = True
                    browser_result = self._try_browser_solve(
                        challenge, current_url
                    )
                    if isinstance(browser_result, WaferResponse):
                        self._record_success(domain)
                        self._record_url(current_url)
                        browser_result.elapsed = (
                            time.monotonic() - start_time
                        )
                        return browser_result
                    if browser_result:
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
                            raw=resp,
                        )
                    raise ChallengeDetected(
                        challenge.value, current_url, status
                    )

                # Fallback: rotate fingerprint
                if not state.can_rotate:
                    # Last resort: browser solve (once per request)
                    if (
                        not browser_attempted
                        and self._browser_solver is not None
                        and challenge is not None
                    ):
                        browser_attempted = True
                        browser_result = self._try_browser_solve(
                            challenge, current_url
                        )
                        if isinstance(browser_result, WaferResponse):
                            self._record_success(domain)
                            self._record_url(current_url)
                            browser_result.elapsed = (
                                time.monotonic() - start_time
                            )
                            return browser_result
                        if browser_result:
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
                                raw=resp,
                            )
                        raise ChallengeDetected(
                            challenge.value, current_url, status
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
                        raw=resp,
                    )
                state.use_rotation()
                if should_retire:
                    self._retire_session(domain)
                else:
                    # Clear domain cookies on every rotation - stale
                    # cookies from a different TLS identity cause WAF
                    # re-challenges (cf_clearance, _abck are TLS-bound).
                    if self._cookie_cache:
                        self._cookie_cache.clear(domain)
                    if state.rotation_retries == 1:
                        pass  # first rotation: just fresh TLS + cleared cookies
                    elif (
                        self._fingerprint is not None
                        and not self._tried_safari
                    ):
                        self._switch_to_safari()
                    elif (
                        self._safari_identity is not None
                        and self._profile is not Profile.SAFARI
                    ):
                        self._switch_to_chrome()
                    elif self._fingerprint is not None:
                        self._fingerprint.rotate()
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
                time.sleep(delay)
                continue

            # 200 with empty text body → normal retry (skip for binary)
            if (
                body is not None
                and status == 200
                and not body.strip()
            ):
                if not state.can_retry:
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
                            raw=resp,
                        )
                    raise EmptyResponse(current_url, status)
                state.use_retry()
                delay = calculate_backoff(state.normal_retries - 1)
                logger.debug(
                    "Empty 200 body, retry %d/%d in %.1fs",
                    state.normal_retries, state.max_retries, delay,
                )
                time.sleep(delay)
                continue

            # Success — reset failure counter, pin fingerprint, track URL
            self._record_success(domain)
            self._record_url(current_url)
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
                raw=resp,
            )

    def get(self, url: str, **kwargs) -> WaferResponse:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> WaferResponse:
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs) -> WaferResponse:
        return self.request("PUT", url, **kwargs)

    def delete(self, url: str, **kwargs) -> WaferResponse:
        return self.request("DELETE", url, **kwargs)

    def head(self, url: str, **kwargs) -> WaferResponse:
        return self.request("HEAD", url, **kwargs)

    def options(self, url: str, **kwargs) -> WaferResponse:
        return self.request("OPTIONS", url, **kwargs)

    def patch(self, url: str, **kwargs) -> WaferResponse:
        return self.request("PATCH", url, **kwargs)

    def add_cookie(self, raw_set_cookie: str, url: str) -> None:
        """Inject a Set-Cookie header value into the session's cookie jar."""
        if self._profile is Profile.OPERA_MINI:
            raise NotImplementedError(
                "add_cookie() is not supported with Opera Mini profile"
            )
        self._client.cookie_jar.add(raw_set_cookie, url)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        if self._browser_solver is not None:
            try:
                self._browser_solver.close()
            except Exception:
                logger.debug("BrowserSolver.close() failed", exc_info=True)
