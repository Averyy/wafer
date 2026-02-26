"""Tests for cookie cache."""

import json
import time

from wafer._cookies import (
    CookieCache,
    _parse_cookie_expires,
    _parse_cookie_name,
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
