"""Tests for the PSL-lite module and its two call sites.

PSL-lite is a curated subset of multi-label public suffixes (NOT the full
Mozilla PSL). It exists so that multi-label suffixes like co.uk / com.au /
github.io are treated as public suffixes for same-site classification and
cookie-domain matching.
"""

from unittest.mock import patch

from tests.conftest import MockResponse, make_sync_session
from wafer import _psl


class TestPublicSuffix:
    def test_bare_tld(self):
        assert _psl.public_suffix("example.com") == "com"
        assert _psl.public_suffix("example.ca") == "ca"

    def test_multi_label_uk(self):
        assert _psl.public_suffix("foo.co.uk") == "co.uk"
        assert _psl.public_suffix("a.b.co.uk") == "co.uk"
        assert _psl.public_suffix("dept.ac.uk") == "ac.uk"

    def test_multi_label_au(self):
        assert _psl.public_suffix("shop.com.au") == "com.au"

    def test_github_io(self):
        assert _psl.public_suffix("alice.github.io") == "github.io"

    def test_newly_added_suffixes(self):
        # FIX 2: curated-subset expansion.
        assert _psl.public_suffix("shop.co.id") == "co.id"
        assert _psl.public_suffix("foo.com.ng") == "com.ng"
        assert _psl.public_suffix("foo.co.th") == "co.th"
        assert _psl.public_suffix("foo.co.ke") == "co.ke"
        assert _psl.public_suffix("alice.blogspot.com") == "blogspot.com"
        assert (
            _psl.public_suffix("app.azurewebsites.net") == "azurewebsites.net"
        )

    def test_empty(self):
        assert _psl.public_suffix("") == ""

    def test_case_insensitive(self):
        assert _psl.public_suffix("Foo.CO.UK") == "co.uk"

    def test_unlisted_multi_label_degrades_to_tld(self):
        # An obscure multi-label TLD not in the curated set falls back to
        # the bare final label (the prior TLD+1 behavior).
        assert _psl.public_suffix("foo.co.zz") == "zz"


class TestRegistrableDomain:
    def test_plain_com(self):
        assert _psl.registrable_domain("www.example.com") == "example.com"
        assert _psl.registrable_domain("example.com") == "example.com"
        assert _psl.registrable_domain("a.b.c.example.com") == "example.com"

    def test_co_uk(self):
        assert _psl.registrable_domain("www.example.co.uk") == "example.co.uk"
        assert _psl.registrable_domain("example.co.uk") == "example.co.uk"

    def test_com_au(self):
        assert _psl.registrable_domain("shop.example.com.au") == "example.com.au"

    def test_github_io(self):
        # Each github.io subdomain is its own registrable domain.
        assert _psl.registrable_domain("alice.github.io") == "alice.github.io"

    def test_bare_public_suffix_unchanged(self):
        # A bare public suffix has nothing registrable above it.
        assert _psl.registrable_domain("co.uk") == "co.uk"
        assert _psl.registrable_domain("com") == "com"

    def test_empty(self):
        assert _psl.registrable_domain("") == ""


class TestSameSite:
    def test_plain_subdomains_same_site(self):
        assert _psl.same_site("www.example.com", "api.example.com")
        assert _psl.same_site("example.com", "www.example.com")

    def test_different_registrable_cross_site(self):
        assert not _psl.same_site("example.com", "other.com")

    def test_co_uk_siblings_cross_site(self):
        # Two unrelated co.uk domains are NOT same-site.
        assert not _psl.same_site("a.co.uk", "b.co.uk")
        assert not _psl.same_site("alice.co.uk", "bob.co.uk")

    def test_co_uk_same_registrable_same_site(self):
        assert _psl.same_site("www.example.co.uk", "api.example.co.uk")

    def test_com_au_siblings_cross_site(self):
        assert not _psl.same_site("shop.com.au", "bank.com.au")

    def test_github_io_siblings_cross_site(self):
        assert not _psl.same_site("alice.github.io", "bob.github.io")

    def test_bare_suffix_never_same_site(self):
        assert not _psl.same_site("co.uk", "co.uk")
        assert not _psl.same_site("com", "com")

    def test_empty_never_same_site(self):
        assert not _psl.same_site("", "example.com")
        assert not _psl.same_site("example.com", "")


class TestCookiesRegistrableDomainDelegates:
    """wafer._cookies.registrable_domain is now PSL-aware."""

    def test_delegates_to_psl(self):
        from wafer._cookies import registrable_domain

        assert registrable_domain("api2.realtor.ca") == "realtor.ca"
        assert registrable_domain("www.example.co.uk") == "example.co.uk"
        assert registrable_domain("alice.github.io") == "alice.github.io"
        assert registrable_domain("") == ""


class TestCookieAppliesToHostPSL:
    """BaseSession._cookie_applies_to_host rejects public-suffix Domains."""

    def _applies(self, cookie_domain, host):
        from wafer._base import BaseSession

        return BaseSession._cookie_applies_to_host(cookie_domain, host)

    def test_ordinary_domain_still_applies(self):
        assert self._applies(".example.com", "www.example.com")
        assert self._applies("example.com", "example.com")
        assert self._applies(".example.co.uk", "www.example.co.uk")

    def test_unrelated_host_does_not_apply(self):
        assert not self._applies(".example.com", "evil.com")

    def test_public_suffix_domain_rejected(self):
        # A Domain=co.uk cookie must NOT apply to a sibling victim.co.uk.
        assert not self._applies("co.uk", "victim.co.uk")
        assert not self._applies(".co.uk", "victim.co.uk")
        assert not self._applies("com.au", "victim.com.au")
        assert not self._applies("github.io", "victim.github.io")

    def test_newly_covered_suffixes_reject_sibling(self):
        # FIX 2: suffixes added to the curated subset now reject siblings
        # instead of fail-open over-matching them.
        assert not self._applies("co.id", "victim.co.id")
        assert not self._applies(".co.id", "victim.co.id")
        assert not self._applies("com.ng", "victim.com.ng")
        assert not self._applies("co.th", "victim.co.th")
        assert not self._applies("co.ke", "victim.co.ke")
        # Hosting suffix where every subdomain is a distinct owner.
        assert not self._applies("blogspot.com", "alice.blogspot.com")
        assert not self._applies(
            "azurewebsites.net", "victim.azurewebsites.net"
        )

    def test_bare_tld_domain_rejected(self):
        assert not self._applies("com", "victim.com")

    def test_localhost_domain_applies(self):
        # localhost is reserved, not a public suffix (RFC 6265 5.3):
        # a Domain=localhost cookie applies to the localhost host.
        assert self._applies("localhost", "localhost")

    def test_trailing_dot_host_matches(self):
        # FIX 3: an absolute-form host (FQDN trailing dot) is normalized
        # so Domain=example.com still matches www.example.com.
        assert self._applies("example.com", "www.example.com.")
        assert self._applies(".example.com", "example.com.")
        assert self._applies("example.com", "example.com.")
        # The rejection path also survives the trailing dot.
        assert not self._applies(".example.com", "evil.com.")


class TestSecFetchSitePSL:
    """_compute_sec_fetch_site is PSL-aware for the same-site case."""

    @patch("time.sleep")
    def test_same_registrable_is_same_site(self, _sleep):
        session, _ = make_sync_session(
            [MockResponse(200, body="ok")],
            embed="xhr",
            embed_origin="https://www.example.co.uk",
        )
        assert (
            session._compute_sec_fetch_site("https://api.example.co.uk/data")
            == "same-site"
        )

    @patch("time.sleep")
    def test_co_uk_siblings_are_cross_site(self, _sleep):
        # Public-suffix-aware: two different co.uk sites are cross-site.
        session, _ = make_sync_session(
            [MockResponse(200, body="ok")],
            embed="xhr",
            embed_origin="https://alice.co.uk",
        )
        assert (
            session._compute_sec_fetch_site("https://bob.co.uk/data")
            == "cross-site"
        )

    @patch("time.sleep")
    def test_plain_subdomain_same_site(self, _sleep):
        session, _ = make_sync_session(
            [MockResponse(200, body="ok")],
            embed="xhr",
            embed_origin="https://www.example.com",
        )
        assert (
            session._compute_sec_fetch_site("https://api.example.com/x")
            == "same-site"
        )

    @patch("time.sleep")
    def test_same_origin(self, _sleep):
        session, _ = make_sync_session(
            [MockResponse(200, body="ok")],
            embed="xhr",
            embed_origin="https://www.example.com",
        )
        assert (
            session._compute_sec_fetch_site("https://www.example.com/x")
            == "same-origin"
        )
