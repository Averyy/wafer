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
