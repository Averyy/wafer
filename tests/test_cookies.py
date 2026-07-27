"""Tests for cookie cache."""

import json
import os
import stat
import threading
import time
from unittest.mock import patch

import pytest

from tests.conftest import (
    MockResponse,
    make_async_session,
    make_sync_session,
)
from wafer._cookies import (
    CookieCache,
    _parse_cookie_expires,
    _parse_cookie_name,
    browser_cookie_matches_host,
    extract_domain,
)

# Far-future expiry for tests that don't care about TTL behavior.
_FUTURE = time.time() + 86400

# ---------------------------------------------------------------------------
# extract_domain
# ---------------------------------------------------------------------------


class TestExtractDomain:
    def test_simple_url(self):
        assert extract_domain("https://example.com/path") == "example.com"

    def test_www_subdomain(self):
        assert (
            extract_domain("https://www.example.com/path")
            == "www.example.com"
        )

    def test_no_path(self):
        assert extract_domain("https://example.com") == "example.com"

    def test_port(self):
        assert (
            extract_domain("https://example.com:8443/x")
            == "example.com"
        )

    def test_invalid_url(self):
        assert extract_domain("not-a-url") is None


class TestBrowserCookieScope:
    def test_host_only_cookie_requires_exact_host(self):
        assert browser_cookie_matches_host(
            "api.example.com", "api.example.com"
        )
        assert not browser_cookie_matches_host(
            "www.example.com", "api.example.com"
        )

    def test_domain_cookie_uses_boundary_aware_domain_match(self):
        assert browser_cookie_matches_host(
            ".example.com", "api.example.com"
        )
        assert not browser_cookie_matches_host(
            ".www.example.com", "api.example.com"
        )
        assert not browser_cookie_matches_host(
            ".example.com", "evil-example.com"
        )

    def test_domainless_cookie_fails_closed(self):
        """A custom browser_solver's domain-less cookie must not be rebound
        to the target host. Playwright always populates domain; a solver that
        does not must lose the cookie rather than have it silently scoped."""
        assert not browser_cookie_matches_host("", "api.example.com")
        assert not browser_cookie_matches_host(".", "api.example.com")


class TestCookieScopeMapIsBounded:
    """The host-only bit map must not grow for the session's whole life."""

    def test_scope_map_is_capped_and_keeps_recently_used_entries(self):
        from wafer import SyncSession
        from wafer._base import _MAX_COOKIE_SCOPES

        session = SyncSession()
        hot = ("hot", "example.com", "/")

        def touch_hot():
            session._record_cookie_scope(
                "hot=1; Domain=.example.com; Path=/",
                "https://www.example.com/",
            )

        touch_hot()
        for i in range(_MAX_COOKIE_SCOPES + 500):
            session._record_cookie_scope(f"c{i}=1; Path=/", f"https://h{i}.test/")
            if i % 1000 == 0:
                touch_hot()

        assert len(session._cookie_scopes) <= _MAX_COOKIE_SCOPES
        # Re-recording refreshes recency, so the repeatedly-seen cookie
        # outlives the one-shot entries that pushed the map over the cap.
        assert hot in session._cookie_scopes
        assert ("c0", "h0.test", "/") not in session._cookie_scopes


# ---------------------------------------------------------------------------
# _parse_cookie_name
# ---------------------------------------------------------------------------


class TestParseCookieName:
    def test_simple(self):
        assert (
            _parse_cookie_name("cf_clearance=abc; Path=/")
            == "cf_clearance"
        )

    def test_no_equals(self):
        assert _parse_cookie_name("invalid") is None

    def test_empty_name(self):
        assert _parse_cookie_name("=value") is None

    def test_whitespace_name(self):
        assert _parse_cookie_name(" name =value") == "name"

    def test_complex_value(self):
        assert (
            _parse_cookie_name("token=abc=def; Path=/; Secure")
            == "token"
        )


# ---------------------------------------------------------------------------
# _parse_cookie_expires
# ---------------------------------------------------------------------------


class TestParseCookieExpires:
    def test_max_age(self):
        result = _parse_cookie_expires("name=val; Max-Age=3600")
        assert result > time.time()
        assert result <= time.time() + 3601

    def test_max_age_zero(self):
        result = _parse_cookie_expires("name=val; Max-Age=0")
        assert result >= time.time() - 1
        assert result <= time.time() + 1

    def test_expires_http_date(self):
        result = _parse_cookie_expires(
            "name=val; Expires=Sun, 06 Nov 1994 08:49:37 GMT"
        )
        assert result > 0

    def test_session_cookie(self):
        assert _parse_cookie_expires("name=val; Path=/") == 0.0

    def test_max_age_takes_precedence(self):
        raw = (
            "name=val; "
            "Expires=Sun, 06 Nov 1994 08:49:37 GMT; "
            "Max-Age=3600"
        )
        result = _parse_cookie_expires(raw)
        # max-age wins → future timestamp
        assert result > time.time()

    def test_no_attributes(self):
        assert _parse_cookie_expires("name=val") == 0.0


# ---------------------------------------------------------------------------
# CookieCache: read/write
# ---------------------------------------------------------------------------


class TestCookieCacheReadWrite:
    def test_save_and_load(self, tmp_path):
        cache = CookieCache(cache_dir=str(tmp_path), max_entries=50)
        cookies = [
            {
                "name": "sess",
                "raw": "sess=abc",
                "url": "https://example.com",
                "expires": _FUTURE,
            },
        ]
        cache.save("example.com", cookies)
        loaded = cache.load("example.com")
        assert len(loaded) == 1
        assert loaded[0]["name"] == "sess"
        assert loaded[0]["raw"] == "sess=abc"

    def test_load_empty(self, tmp_path):
        cache = CookieCache(cache_dir=str(tmp_path))
        assert cache.load("nonexistent.com") == []

    def test_multiple_cookies(self, tmp_path):
        cache = CookieCache(cache_dir=str(tmp_path))
        cookies = [
            {
                "name": "a",
                "raw": "a=1",
                "url": "https://e.com",
                "expires": _FUTURE,
            },
            {
                "name": "b",
                "raw": "b=2",
                "url": "https://e.com",
                "expires": _FUTURE,
            },
        ]
        cache.save("e.com", cookies)
        loaded = cache.load("e.com")
        names = {c["name"] for c in loaded}
        assert names == {"a", "b"}

    def test_save_empty_list_is_noop(self, tmp_path):
        cache = CookieCache(cache_dir=str(tmp_path))
        cache.save("e.com", [])
        assert cache.load("e.com") == []


# ---------------------------------------------------------------------------
# CookieCache: TTL
# ---------------------------------------------------------------------------


class TestCookieCacheTTL:
    def test_expired_cookies_skipped(self, tmp_path):
        cache = CookieCache(cache_dir=str(tmp_path))
        now = time.time()
        cookies = [
            {
                "name": "expired",
                "raw": "expired=x",
                "url": "https://e.com",
                "expires": now - 10,
            },
            {
                "name": "valid",
                "raw": "valid=x",
                "url": "https://e.com",
                "expires": now + 3600,
            },
        ]
        cache.save("e.com", cookies)
        loaded = cache.load("e.com")
        names = [c["name"] for c in loaded]
        assert "expired" not in names
        assert "valid" in names

    def test_session_cookies_not_persisted(self, tmp_path):
        """Session cookies (expires=0) should not survive disk round-trip."""
        cache = CookieCache(cache_dir=str(tmp_path))
        cookies = [
            {
                "name": "session",
                "raw": "session=x",
                "url": "https://e.com",
                "expires": 0,
            },
            {
                "name": "persistent",
                "raw": "persistent=x",
                "url": "https://e.com",
                "expires": time.time() + 3600,
            },
        ]
        cache.save("e.com", cookies)
        loaded = cache.load("e.com")
        names = [c["name"] for c in loaded]
        assert "session" not in names
        assert "persistent" in names

    def test_all_expired_returns_empty(self, tmp_path):
        cache = CookieCache(cache_dir=str(tmp_path))
        now = time.time()
        cookies = [
            {
                "name": "old",
                "raw": "old=x",
                "url": "https://e.com",
                "expires": now - 100,
            },
        ]
        cache.save("e.com", cookies)
        assert cache.load("e.com") == []

    def test_ttl_compaction_on_save(self, tmp_path):
        """Expired cookies from previous save are compacted on next save."""
        cache = CookieCache(cache_dir=str(tmp_path))
        now = time.time()
        # Save an already-expired cookie
        cache.save(
            "e.com",
            [
                {
                    "name": "old",
                    "raw": "old=x",
                    "url": "https://e.com",
                    "expires": now - 10,
                },
            ],
        )
        # Save a new cookie — the expired one should be compacted away
        cache.save(
            "e.com",
            [
                {
                    "name": "new",
                    "raw": "new=x",
                    "url": "https://e.com",
                    "expires": _FUTURE,
                },
            ],
        )
        # Read raw file — should only have "new"
        path = cache._domain_path("e.com")
        data = json.loads(path.read_text())
        names = {e["name"] for e in data}
        assert "old" not in names
        assert "new" in names


# ---------------------------------------------------------------------------
# CookieCache: LRU eviction
# ---------------------------------------------------------------------------


class TestCookieCacheLRU:
    def test_eviction_keeps_most_recent(self, tmp_path):
        cache = CookieCache(cache_dir=str(tmp_path), max_entries=3)
        now = time.time()
        cookies = [
            {
                "name": f"c{i}",
                "raw": f"c{i}=v",
                "url": "https://e.com",
                "expires": _FUTURE,
                "last_used": now - (10 - i),
            }
            for i in range(5)
        ]
        cache.save("e.com", cookies)
        loaded = cache.load("e.com")
        assert len(loaded) == 3
        names = {c["name"] for c in loaded}
        # Most recently used (highest last_used) should survive
        assert "c4" in names
        assert "c3" in names
        assert "c2" in names

    def test_no_eviction_under_limit(self, tmp_path):
        cache = CookieCache(cache_dir=str(tmp_path), max_entries=10)
        cookies = [
            {
                "name": f"c{i}",
                "raw": f"c{i}=v",
                "url": "https://e.com",
                "expires": _FUTURE,
            }
            for i in range(5)
        ]
        cache.save("e.com", cookies)
        loaded = cache.load("e.com")
        assert len(loaded) == 5

    def test_eviction_at_exact_limit(self, tmp_path):
        cache = CookieCache(cache_dir=str(tmp_path), max_entries=3)
        cookies = [
            {
                "name": f"c{i}",
                "raw": f"c{i}=v",
                "url": "https://e.com",
                "expires": _FUTURE,
            }
            for i in range(3)
        ]
        cache.save("e.com", cookies)
        loaded = cache.load("e.com")
        assert len(loaded) == 3


# ---------------------------------------------------------------------------
# CookieCache: merge / overwrite
# ---------------------------------------------------------------------------


class TestCookieCacheMerge:
    def test_overwrites_same_name(self, tmp_path):
        cache = CookieCache(cache_dir=str(tmp_path))
        cache.save(
            "e.com",
            [
                {
                    "name": "a",
                    "raw": "a=old",
                    "url": "https://e.com",
                    "expires": _FUTURE,
                },
            ],
        )
        cache.save(
            "e.com",
            [
                {
                    "name": "a",
                    "raw": "a=new",
                    "url": "https://e.com",
                    "expires": _FUTURE,
                },
            ],
        )
        loaded = cache.load("e.com")
        assert len(loaded) == 1
        assert loaded[0]["raw"] == "a=new"

    def test_merges_different_names(self, tmp_path):
        cache = CookieCache(cache_dir=str(tmp_path))
        cache.save(
            "e.com",
            [
                {
                    "name": "a",
                    "raw": "a=1",
                    "url": "https://e.com",
                    "expires": _FUTURE,
                },
            ],
        )
        cache.save(
            "e.com",
            [
                {
                    "name": "b",
                    "raw": "b=2",
                    "url": "https://e.com",
                    "expires": _FUTURE,
                },
            ],
        )
        loaded = cache.load("e.com")
        names = {c["name"] for c in loaded}
        assert names == {"a", "b"}

    def test_same_name_on_different_paths_survives(self, tmp_path):
        cache = CookieCache(cache_dir=str(tmp_path))
        cache.save(
            "e.com",
            [
                {
                    "name": "sid",
                    "raw": "sid=root; Path=/",
                    "url": "https://e.com/",
                    "expires": _FUTURE,
                },
                {
                    "name": "sid",
                    "raw": "sid=api; Path=/api",
                    "url": "https://e.com/api",
                    "expires": _FUTURE,
                },
            ],
        )

        loaded = cache.load("e.com")

        assert {cookie["raw"] for cookie in loaded} == {
            "sid=root; Path=/",
            "sid=api; Path=/api",
        }

    def test_same_name_on_different_domains_survives(self, tmp_path):
        cache = CookieCache(cache_dir=str(tmp_path))
        cache.save(
            "example.com",
            [
                {
                    "name": "sid",
                    "raw": "sid=site; Domain=.example.com; Path=/",
                    "url": "https://example.com/",
                    "expires": _FUTURE,
                },
                {
                    "name": "sid",
                    "raw": "sid=api; Domain=api.example.com; Path=/",
                    "url": "https://api.example.com/",
                    "expires": _FUTURE,
                },
            ],
        )

        loaded = cache.load("example.com")

        assert {cookie["raw"] for cookie in loaded} == {
            "sid=site; Domain=.example.com; Path=/",
            "sid=api; Domain=api.example.com; Path=/",
        }

    def test_implicit_default_paths_do_not_collide(self, tmp_path):
        cache = CookieCache(cache_dir=str(tmp_path))

        cache.save_from_headers(
            "example.com",
            ["sid=alpha; Max-Age=3600"],
            "https://example.com/alpha/item",
        )
        cache.save_from_headers(
            "example.com",
            ["sid=beta; Max-Age=3600"],
            "https://example.com/beta/item",
        )

        assert {cookie["raw"] for cookie in cache.load("example.com")} == {
            "sid=alpha; Max-Age=3600",
            "sid=beta; Max-Age=3600",
        }


# ---------------------------------------------------------------------------
# CookieCache: corrupt files
# ---------------------------------------------------------------------------


class TestCookieCacheCorrupt:
    def test_invalid_json(self, tmp_path):
        cache = CookieCache(cache_dir=str(tmp_path))
        path = cache._domain_path("bad.com")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("not json{{{")
        assert cache.load("bad.com") == []

    def test_json_not_list(self, tmp_path):
        cache = CookieCache(cache_dir=str(tmp_path))
        path = cache._domain_path("bad.com")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('{"key": "value"}')
        assert cache.load("bad.com") == []

    def test_json_null(self, tmp_path):
        cache = CookieCache(cache_dir=str(tmp_path))
        path = cache._domain_path("bad.com")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("null")
        assert cache.load("bad.com") == []

    def test_empty_file(self, tmp_path):
        cache = CookieCache(cache_dir=str(tmp_path))
        path = cache._domain_path("bad.com")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("")
        assert cache.load("bad.com") == []

    def test_invalid_list_entries_do_not_poison_valid_cookies(self, tmp_path):
        cache = CookieCache(cache_dir=str(tmp_path))
        path = cache._domain_path("mixed.com")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                [
                    "not-a-cookie",
                    {
                        "name": "valid",
                        "raw": "valid=yes; Path=/",
                        "url": "https://mixed.com/",
                        "expires": _FUTURE,
                    },
                ]
            )
        )

        assert [entry["name"] for entry in cache.load("mixed.com")] == [
            "valid"
        ]

    def test_invalid_timestamp_types_do_not_poison_cache(self, tmp_path):
        cache = CookieCache(cache_dir=str(tmp_path))
        path = cache._domain_path("mixed.com")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                [
                    {
                        "name": "bad",
                        "raw": "bad=no",
                        "url": "https://mixed.com/",
                        "expires": {"not": "numeric"},
                        "last_used": ["not", "numeric"],
                    },
                    {
                        "name": "valid",
                        "raw": "valid=yes",
                        "url": "https://mixed.com/",
                        "expires": _FUTURE,
                    },
                ]
            )
        )

        assert [entry["name"] for entry in cache.load("mixed.com")] == [
            "valid"
        ]
        cache.save(
            "mixed.com",
            [
                {
                    "name": "next",
                    "raw": "next=yes",
                    "url": "https://mixed.com/",
                    "expires": _FUTURE,
                }
            ],
        )
        assert {entry["name"] for entry in cache.load("mixed.com")} == {
            "valid",
            "next",
        }


# ---------------------------------------------------------------------------
# CookieCache: clear / list_domains
# ---------------------------------------------------------------------------


class TestCookieCacheClearAndList:
    def test_clear_removes_file(self, tmp_path):
        cache = CookieCache(cache_dir=str(tmp_path))
        cache.save(
            "e.com",
            [
                {
                    "name": "a",
                    "raw": "a=v",
                    "url": "https://e.com",
                    "expires": _FUTURE,
                },
            ],
        )
        assert cache.load("e.com") != []
        cache.clear("e.com")
        assert cache.load("e.com") == []

    def test_clear_nonexistent(self, tmp_path):
        cache = CookieCache(cache_dir=str(tmp_path))
        cache.clear("nope.com")  # should not raise

    def test_list_domains(self, tmp_path):
        cache = CookieCache(cache_dir=str(tmp_path))
        cache.save(
            "a.com",
            [
                {
                    "name": "x",
                    "raw": "x=1",
                    "url": "https://a.com",
                    "expires": _FUTURE,
                },
            ],
        )
        cache.save(
            "b.com",
            [
                {
                    "name": "y",
                    "raw": "y=2",
                    "url": "https://b.com",
                    "expires": _FUTURE,
                },
            ],
        )
        domains = cache.list_domains()
        assert set(domains) == {"a.com", "b.com"}

    def test_list_domains_empty(self, tmp_path):
        cache = CookieCache(cache_dir=str(tmp_path / "empty"))
        assert cache.list_domains() == []


# ---------------------------------------------------------------------------
# CookieCache: save_from_headers
# ---------------------------------------------------------------------------


class TestSaveFromHeaders:
    def test_bytes_values(self, tmp_path):
        cache = CookieCache(cache_dir=str(tmp_path))
        raw_values = [
            b"cf_clearance=abc123; Max-Age=1800; Path=/; Secure; HttpOnly",
            b"token=xyz; Max-Age=3600; Path=/",
        ]
        cache.save_from_headers(
            "example.com", raw_values, "https://example.com/page"
        )
        loaded = cache.load("example.com")
        assert len(loaded) == 2
        names = {c["name"] for c in loaded}
        assert "cf_clearance" in names
        assert "token" in names

    def test_preserves_raw_value(self, tmp_path):
        cache = CookieCache(cache_dir=str(tmp_path))
        raw = b"token=abc123; Max-Age=3600; Path=/; Domain=.example.com; Secure"
        cache.save_from_headers(
            "example.com", [raw], "https://example.com"
        )
        loaded = cache.load("example.com")
        assert loaded[0]["raw"] == raw.decode()

    def test_preserves_url(self, tmp_path):
        cache = CookieCache(cache_dir=str(tmp_path))
        cache.save_from_headers(
            "e.com",
            [b"a=1; Max-Age=3600; Path=/"],
            "https://e.com/path?q=1",
        )
        loaded = cache.load("e.com")
        assert loaded[0]["url"] == "https://e.com/path?q=1"

    def test_with_max_age(self, tmp_path):
        cache = CookieCache(cache_dir=str(tmp_path))
        cache.save_from_headers(
            "e.com",
            [b"token=abc; Max-Age=3600; Path=/"],
            "https://e.com",
        )
        loaded = cache.load("e.com")
        assert len(loaded) == 1
        assert loaded[0]["expires"] > time.time()

    def test_empty_list(self, tmp_path):
        cache = CookieCache(cache_dir=str(tmp_path))
        cache.save_from_headers("e.com", [], "https://e.com")
        assert cache.load("e.com") == []

    def test_invalid_cookie_skipped(self, tmp_path):
        cache = CookieCache(cache_dir=str(tmp_path))
        cache.save_from_headers(
            "e.com",
            [b"=noname; Path=/", b"valid=yes; Max-Age=3600; Path=/"],
            "https://e.com",
        )
        loaded = cache.load("e.com")
        assert len(loaded) == 1
        assert loaded[0]["name"] == "valid"


# ---------------------------------------------------------------------------
# CookieCache: atomic writes + directory creation
# ---------------------------------------------------------------------------


class TestCookieCacheAtomic:
    def test_creates_nested_dirs(self, tmp_path):
        cache = CookieCache(
            cache_dir=str(tmp_path / "deep" / "nested")
        )
        cache.save(
            "e.com",
            [
                {
                    "name": "a",
                    "raw": "a=v",
                    "url": "https://e.com",
                    "expires": _FUTURE,
                },
            ],
        )
        assert cache.load("e.com")[0]["name"] == "a"

    def test_file_is_valid_json(self, tmp_path):
        cache = CookieCache(cache_dir=str(tmp_path))
        cache.save(
            "e.com",
            [
                {
                    "name": "a",
                    "raw": "a=v",
                    "url": "https://e.com",
                    "expires": _FUTURE,
                },
            ],
        )
        path = cache._domain_path("e.com")
        data = json.loads(path.read_text())
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["name"] == "a"

    def test_no_tmp_files_left(self, tmp_path):
        cache = CookieCache(cache_dir=str(tmp_path))
        cache.save(
            "e.com",
            [
                {
                    "name": "a",
                    "raw": "a=v",
                    "url": "https://e.com",
                    "expires": _FUTURE,
                },
            ],
        )
        tmp_files = list(tmp_path.glob("*.tmp"))
        assert tmp_files == []

    def test_file_and_directory_are_fsynced(self, tmp_path):
        cache = CookieCache(cache_dir=str(tmp_path))
        with (
            patch("wafer._cookies.os.fsync") as fsync,
            patch(
                "wafer._cookies.os.replace",
                wraps=os.replace,
            ) as replace,
        ):
            cache.save(
                "e.com",
                [
                    {
                        "name": "a",
                        "raw": "a=v",
                        "url": "https://e.com",
                        "expires": _FUTURE,
                    },
                ],
            )

        assert fsync.call_count == (1 if os.name == "nt" else 2)
        replace.assert_called_once()

    def test_failed_file_fsync_preserves_previous_file(self, tmp_path):
        cache = CookieCache(cache_dir=str(tmp_path))
        cache.save(
            "e.com",
            [
                {
                    "name": "a",
                    "raw": "a=old",
                    "url": "https://e.com",
                    "expires": _FUTURE,
                },
            ],
        )

        with (
            patch(
                "wafer._cookies.os.fsync",
                side_effect=OSError("disk flush failed"),
            ),
            pytest.raises(OSError, match="disk flush failed"),
        ):
            cache.save(
                "e.com",
                [
                    {
                        "name": "a",
                        "raw": "a=new",
                        "url": "https://e.com",
                        "expires": _FUTURE,
                    },
                ],
            )

        assert cache.load("e.com")[0]["raw"] == "a=old"
        assert list(tmp_path.glob("*.tmp")) == []


# ---------------------------------------------------------------------------
# CookieCache: last_used tracking
# ---------------------------------------------------------------------------


class TestCookieCacheLastUsed:
    def test_last_used_updated_on_load(self, tmp_path):
        cache = CookieCache(cache_dir=str(tmp_path))
        old_time = time.time() - 1000
        cache.save(
            "e.com",
            [
                {
                    "name": "a",
                    "raw": "a=v",
                    "url": "https://e.com",
                    "expires": _FUTURE,
                    "last_used": old_time,
                },
            ],
        )
        loaded = cache.load("e.com")
        assert loaded[0]["last_used"] > old_time

    def test_last_used_defaults_on_save(self, tmp_path):
        cache = CookieCache(cache_dir=str(tmp_path))
        before = time.time()
        cache.save(
            "e.com",
            [
                {
                    "name": "a",
                    "raw": "a=v",
                    "url": "https://e.com",
                    "expires": _FUTURE,
                },
            ],
        )
        path = cache._domain_path("e.com")
        data = json.loads(path.read_text())
        assert data[0]["last_used"] >= before


# ---------------------------------------------------------------------------
# Session integration (mocked)
# ---------------------------------------------------------------------------


class TestSessionCookieCacheDisabled:
    def test_cache_dir_none_disables_cache(self):
        """When cache_dir=None, _cookie_cache should be None."""
        from wafer._base import BaseSession

        bs = BaseSession(cache_dir=None)
        assert bs._cookie_cache is None

    def test_cookie_cache_none_by_default(self):
        """Default cache_dir=None means no disk cache."""
        from wafer._base import BaseSession

        bs = BaseSession()
        assert bs._cookie_cache is None

    def test_cookie_cache_created_with_path(self):
        from wafer._base import BaseSession

        bs = BaseSession(cache_dir="./data/wafer/cookies")
        assert bs._cookie_cache is not None


class TestSessionCookieScope:
    def test_host_only_cookie_does_not_leak_to_subdomain(self):
        session, _ = make_sync_session(
            [MockResponse(200)], use_cookie_jar=True
        )
        session.add_cookie("sid=host; Path=/", "https://example.com/")

        assert session.get_cookie("sid", "https://example.com/") == "host"
        assert session.get_cookie(
            "sid", "https://www.example.com/"
        ) is None

    def test_domain_cookie_honors_path_on_subdomain(self):
        session, _ = make_sync_session(
            [MockResponse(200)], use_cookie_jar=True
        )
        session.add_cookie(
            "sid=admin; Domain=.example.com; Path=/admin",
            "https://example.com/admin/login",
        )

        assert session.get_cookie(
            "sid", "https://api.example.com/public"
        ) is None
        assert session.get_cookie(
            "sid", "https://api.example.com/admin/users"
        ) == "admin"

    def test_longest_matching_cookie_path_wins(self):
        session, _ = make_sync_session(
            [MockResponse(200)], use_cookie_jar=True
        )
        session.add_cookie(
            "sid=root; Domain=.example.com; Path=/",
            "https://example.com/",
        )
        session.add_cookie(
            "sid=admin; Domain=.example.com; Path=/admin",
            "https://example.com/admin/login",
        )

        assert session.get_cookie(
            "sid", "https://api.example.com/admin/users"
        ) == "admin"

    def test_exact_host_breaks_equal_path_tie(self):
        session, _ = make_sync_session(
            [MockResponse(200)], use_cookie_jar=True
        )
        session.add_cookie(
            "sid=parent; Domain=.example.com; Path=/",
            "https://example.com/",
        )
        session.add_cookie(
            "sid=host; Path=/",
            "https://api.example.com/",
        )

        assert session.get_cookie(
            "sid", "https://api.example.com/"
        ) == "host"

    def test_response_cookie_scope_is_recorded_without_disk_cache(self):
        session, _ = make_sync_session(
            [
                MockResponse(
                    200,
                    {"set-cookie": "sid=host; Path=/"},
                    "ok",
                )
            ],
            use_cookie_jar=True,
            cookie_cache=None,
        )

        session.get("https://example.com/")

        assert session.get_cookie(
            "sid", "https://www.example.com/"
        ) is None

    @pytest.mark.asyncio
    async def test_async_response_cookie_scope_is_recorded_without_cache(
        self,
    ):
        session, _ = make_async_session(
            [
                MockResponse(
                    200,
                    {"set-cookie": "sid=host; Path=/"},
                    "ok",
                )
            ],
            use_cookie_jar=True,
            cookie_cache=None,
        )

        await session.get("https://example.com/")

        assert session.get_cookie(
            "sid", "https://www.example.com/"
        ) is None


# ---------------------------------------------------------------------------
# CookieCache: concurrent writers
# ---------------------------------------------------------------------------


class TestCookieCacheConcurrency:
    def test_concurrent_saves_no_lost_updates(self, tmp_path):
        """Two threads writing distinct cookie names must both survive."""
        cache = CookieCache(cache_dir=str(tmp_path), max_entries=500)
        per_thread = 200
        barrier = threading.Barrier(2)

        def writer(prefix):
            barrier.wait()
            for i in range(per_thread):
                cache.save(
                    "e.com",
                    [
                        {
                            "name": f"{prefix}{i}",
                            "raw": f"{prefix}{i}=v",
                            "url": "https://e.com",
                            "expires": _FUTURE,
                        },
                    ],
                )

        t1 = threading.Thread(target=writer, args=("a",))
        t2 = threading.Thread(target=writer, args=("b",))
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        loaded = cache.load("e.com")
        names = {c["name"] for c in loaded}
        assert len(names) == per_thread * 2

    def test_clear_serializes_with_domain_writer(self, tmp_path):
        cache = CookieCache(cache_dir=str(tmp_path))
        domain_lock = cache._get_domain_lock("e.com")
        clear_started = threading.Event()
        clear_finished = threading.Event()

        def clearer():
            clear_started.set()
            cache.clear("e.com")
            clear_finished.set()

        domain_lock.acquire()
        thread = threading.Thread(target=clearer)
        try:
            thread.start()
            assert clear_started.wait(timeout=1)
            assert not clear_finished.wait(timeout=0.05)
        finally:
            domain_lock.release()
        thread.join(timeout=1)
        assert clear_finished.is_set()

    def test_sanitized_path_aliases_share_one_lock(self, tmp_path):
        cache = CookieCache(cache_dir=str(tmp_path))

        assert cache._domain_path("a:b") == cache._domain_path("a_b")
        assert cache._get_domain_lock("a:b") is cache._get_domain_lock("a_b")


# ---------------------------------------------------------------------------
# File permissions -- cookie files hold WAF-clearance / auth tokens
# ---------------------------------------------------------------------------


class TestCookieFilePermissions:
    @pytest.mark.skipif(
        os.name == "nt", reason="POSIX file modes not applicable on Windows"
    )
    def test_cookie_file_is_owner_only(self, tmp_path):
        cache = CookieCache(cache_dir=str(tmp_path / "cc"))
        cache.save(
            "example.com",
            [
                {
                    "name": "cf_clearance",
                    "value": "secret",
                    "domain": "example.com",
                    "path": "/",
                    "expires": _FUTURE,
                }
            ],
        )
        files = list((tmp_path / "cc").glob("*.json"))
        assert files, "expected a cookie file to be written"
        for f in files:
            mode = stat.S_IMODE(os.stat(f).st_mode)
            assert mode == 0o600, f"{f.name} mode {oct(mode)} != 0o600"

    @pytest.mark.skipif(
        os.name == "nt", reason="POSIX dir modes not applicable on Windows"
    )
    def test_wafer_created_cache_dir_is_owner_only(self, tmp_path):
        # wafer creates the leaf dir on first write -> should be 0o700.
        cache_dir = tmp_path / "newcc"
        cache = CookieCache(cache_dir=str(cache_dir))
        cache.save(
            "example.com",
            [
                {
                    "name": "a",
                    "value": "1",
                    "domain": "example.com",
                    "path": "/",
                    "expires": _FUTURE,
                }
            ],
        )
        mode = stat.S_IMODE(os.stat(cache_dir).st_mode)
        assert mode == 0o700, f"cache dir mode {oct(mode)} != 0o700"
