"""Tests for session.add_cookie() / session.get_cookie() public cookie access."""


from wafer import AsyncSession, Profile, SyncSession


class TestSyncAddCookie:
    def test_add_cookie_is_callable(self):
        """SyncSession.add_cookie exists and is callable."""
        session = SyncSession(cache_dir=None)
        assert callable(session.add_cookie)

    def test_add_cookie_signature(self):
        """add_cookie accepts (raw_set_cookie, url) args."""
        session = SyncSession(cache_dir=None)
        # Should not raise -- injects cookie into jar
        session.add_cookie("test=value; Path=/", "https://example.com")

    def test_add_cookie_multiple(self):
        """Multiple add_cookie calls don't raise."""
        session = SyncSession(cache_dir=None)
        session.add_cookie("a=1; Path=/", "https://example.com")
        session.add_cookie("b=2; Path=/; Secure", "https://example.com")


class TestAsyncAddCookie:
    def test_add_cookie_is_callable(self):
        """AsyncSession.add_cookie exists and is callable."""
        session = AsyncSession(cache_dir=None)
        assert callable(session.add_cookie)

    def test_add_cookie_signature(self):
        """add_cookie accepts (raw_set_cookie, url) args."""
        session = AsyncSession(cache_dir=None)
        # Should not raise -- injects cookie into jar
        session.add_cookie("test=value; Path=/", "https://example.com")

    def test_add_cookie_multiple(self):
        """Multiple add_cookie calls don't raise."""
        session = AsyncSession(cache_dir=None)
        session.add_cookie("a=1; Path=/", "https://example.com")
        session.add_cookie("b=2; Path=/; Secure", "https://example.com")


class TestSyncGetCookie:
    def test_get_cookie_roundtrip(self):
        """add_cookie then get_cookie returns the value."""
        session = SyncSession(cache_dir=None)
        session.add_cookie("test=value123; Path=/", "https://example.com")
        assert (
            session.get_cookie("test", "https://example.com") == "value123"
        )

    def test_get_cookie_missing_returns_none(self):
        session = SyncSession(cache_dir=None)
        assert session.get_cookie("nope", "https://example.com") is None

    def test_get_cookie_parent_domain_matches_subdomain(self):
        """Domain=.example.com cookie is visible from www.example.com."""
        session = SyncSession(cache_dir=None)
        session.add_cookie(
            "tok=abc; Domain=.example.com; Path=/", "https://example.com"
        )
        assert (
            session.get_cookie("tok", "https://www.example.com") == "abc"
        )

    def test_get_cookie_other_domain_returns_none(self):
        """Cookies don't leak across unrelated domains."""
        session = SyncSession(cache_dir=None)
        session.add_cookie("tok=abc; Path=/", "https://example.com")
        assert session.get_cookie("tok", "https://other.com") is None

    def test_get_cookie_reads_native_tls_jar(self):
        """Cookies in the native-TLS (Imperva bypass) jar are readable."""
        session = SyncSession(cache_dir=None)
        transport = session._native_transport()
        transport.add_cookies(
            [
                {
                    "name": "reese84",
                    "value": "tok123",
                    "domain": ".example.com",
                    "path": "/",
                }
            ]
        )
        assert (
            session.get_cookie("reese84", "https://api.example.com/x")
            == "tok123"
        )

    def test_get_cookie_opera_mini_graceful(self):
        """Opera Mini (no wreq client) returns None instead of crashing."""
        session = SyncSession(profile=Profile.OPERA_MINI)
        assert session.get_cookie("x", "https://example.com") is None


def _http_cookiejar_cookie(name, value, domain, secure):
    from http.cookiejar import Cookie

    return Cookie(
        version=0, name=name, value=value,
        port=None, port_specified=False,
        domain=domain, domain_specified=bool(domain),
        domain_initial_dot=domain.startswith("."),
        path="/", path_specified=True,
        secure=secure, expires=None, discard=True,
        comment=None, comment_url=None, rest={}, rfc2109=False,
    )


class TestGetCookieSecure:
    """Secure cookies must never be returned for non-https URLs."""

    def test_wreq_jar_secure_skipped_over_http(self):
        session = SyncSession(cache_dir=None)
        session.add_cookie("tok=abc; Path=/; Secure", "https://example.com")
        assert session.get_cookie("tok", "http://example.com") is None
        assert session.get_cookie("tok", "https://example.com") == "abc"

    def test_wreq_jar_non_secure_still_returned_over_http(self):
        session = SyncSession(cache_dir=None)
        session.add_cookie("tok=abc; Path=/", "https://example.com")
        assert session.get_cookie("tok", "http://example.com") == "abc"

    def test_wreq_jar_secure_parent_domain_skipped_over_http(self):
        """The parent-domain scan branch must enforce Secure too."""
        session = SyncSession(cache_dir=None)
        session.add_cookie(
            "tok=abc; Domain=.example.com; Path=/; Secure",
            "https://example.com",
        )
        assert session.get_cookie("tok", "http://www.example.com") is None
        assert (
            session.get_cookie("tok", "https://www.example.com") == "abc"
        )

    def test_native_tls_jar_secure_skipped_over_http(self):
        session = SyncSession(cache_dir=None)
        session._native_transport().add_cookies(
            [
                {
                    "name": "reese84",
                    "value": "tok123",
                    "domain": ".example.com",
                    "path": "/",
                    "secure": True,
                }
            ]
        )
        assert (
            session.get_cookie("reese84", "http://api.example.com/x")
            is None
        )
        assert (
            session.get_cookie("reese84", "https://api.example.com/x")
            == "tok123"
        )

    def test_opera_mini_jar_secure_skipped_over_http(self):
        session = SyncSession(profile=Profile.OPERA_MINI)
        session._om_identity._cookie_jar.set_cookie(
            _http_cookiejar_cookie(
                "sid", "s1", ".example.com", secure=True
            )
        )
        session._om_identity._cookie_jar.set_cookie(
            _http_cookiejar_cookie(
                "plain", "p1", ".example.com", secure=False
            )
        )
        assert session.get_cookie("sid", "http://example.com") is None
        assert session.get_cookie("sid", "https://example.com") == "s1"
        assert session.get_cookie("plain", "http://example.com") == "p1"

    def test_async_session_secure_skipped_over_http(self):
        """Parity: AsyncSession.get_cookie enforces Secure too."""
        session = AsyncSession(cache_dir=None)
        session.add_cookie("tok=xyz; Path=/; Secure", "https://example.com")
        assert session.get_cookie("tok", "http://example.com") is None
        assert session.get_cookie("tok", "https://example.com") == "xyz"


class TestAsyncGetCookie:
    def test_get_cookie_roundtrip(self):
        """get_cookie is sync on AsyncSession too (not a coroutine)."""
        session = AsyncSession(cache_dir=None)
        session.add_cookie("test=value456; Path=/", "https://example.com")
        assert (
            session.get_cookie("test", "https://example.com") == "value456"
        )

    def test_get_cookie_missing_returns_none(self):
        session = AsyncSession(cache_dir=None)
        assert session.get_cookie("nope", "https://example.com") is None

    def test_get_cookie_parent_domain_matches_subdomain(self):
        session = AsyncSession(cache_dir=None)
        session.add_cookie(
            "tok=xyz; Domain=.example.com; Path=/", "https://example.com"
        )
        assert (
            session.get_cookie("tok", "https://api.example.com") == "xyz"
        )


class TestHostOnlyCookiesRealJar:
    """Host-only cookies against wreq's real Jar.

    Since wreq 0.12.2, ``Jar.get_all()`` reports a host-only cookie with
    ``domain=None`` instead of the host that set it, which made every
    host-only cookie invisible to get_cookie(). These run on the real jar
    (not conftest's MockJar) so the next change in wreq's jar shows up here.
    """

    def test_wreq_reports_host_only_cookie_without_domain(self):
        # Canary for the wreq behavior the code below compensates for.
        session = SyncSession(cache_dir=None)
        session.add_cookie("h=1; Path=/", "https://www.example.com/")
        (cookie,) = session._client.cookie_jar.get_all()
        assert cookie.domain is None

    def test_host_only_cookie_visible_below_its_path(self):
        session = SyncSession(cache_dir=None)
        session.add_cookie("h=1; Path=/", "https://www.example.com/")
        assert session.get_cookie("h", "https://www.example.com/a/b") == "1"

    def test_same_named_host_only_cookies_stay_on_their_hosts(self):
        session = SyncSession(cache_dir=None)
        session.add_cookie("sid=www; Path=/", "https://www.example.com/")
        session.add_cookie("sid=api; Path=/", "https://api.example.com/")
        assert session.get_cookie("sid", "https://www.example.com/") == "www"
        assert session.get_cookie("sid", "https://api.example.com/") == "api"
        assert session.get_cookie("sid", "https://example.com/") is None
        assert session.get_cookie("sid", "https://other.example.com/") is None

    def test_host_only_beats_parent_domain_on_its_host(self):
        session = SyncSession(cache_dir=None)
        session.add_cookie(
            "sid=parent; Domain=.example.com; Path=/", "https://example.com/"
        )
        session.add_cookie("sid=host; Path=/", "https://api.example.com/")
        assert session.get_cookie("sid", "https://api.example.com/") == "host"
        assert session.get_cookie("sid", "https://www.example.com/") == "parent"

    def test_scope_summary_names_the_host_of_a_host_only_cookie(self):
        session = SyncSession(cache_dir=None)
        session.add_cookie("h=1; Path=/", "https://www.example.com/")
        session.add_cookie("o=2; Path=/", "https://api.example.com/")
        session.add_cookie("d=3; Domain=example.com; Path=/", "https://example.com/")
        domains = {
            entry["name"]: entry["domain"]
            for entry in session.cookie_scope_summary("https://www.example.com/")
        }
        assert domains == {
            "h": "www.example.com",
            "o": "api.example.com",
            "d": "example.com",
        }

    def test_async_session_resolves_host_only_cookie(self):
        session = AsyncSession(cache_dir=None)
        session.add_cookie("h=1; Path=/", "https://www.example.com/")
        assert session.get_cookie("h", "https://www.example.com/") == "1"
        assert session.get_cookie("h", "https://api.example.com/") is None

    def test_same_host_collision_returns_the_cookie_sent_first(self):
        # A host-only cookie and a Domain=<same host> cookie with one name and
        # path both live under that host; the jar sends the earlier-created one
        # first, and get_cookie returns that one in either creation order.
        for first, second, expected in (
            ("sid=dom; Domain=example.com; Path=/", "sid=host; Path=/", "dom"),
            ("sid=host; Path=/", "sid=dom; Domain=example.com; Path=/", "host"),
        ):
            session = SyncSession(cache_dir=None)
            session.add_cookie(first, "https://example.com/")
            session.add_cookie(second, "https://example.com/")
            assert session.get_cookie("sid", "https://example.com/") == expected
