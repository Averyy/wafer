"""Tests for session.add_cookie() public cookie injection."""


from wafer import AsyncSession, SyncSession


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
