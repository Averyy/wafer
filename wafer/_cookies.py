"""Cookie cache: JSON disk persistence with TTL and LRU eviction."""

import email.utils
import json
import logging
import os
import tempfile
import threading
import time
from pathlib import Path
from urllib.parse import urlparse

from wafer import _psl

logger = logging.getLogger("wafer")


def extract_domain(url: str) -> str | None:
    """Extract hostname from a URL."""
    return urlparse(url).hostname


def registrable_domain(host: str) -> str:
    """Registrable domain of ``host``, PSL-lite-aware.

    ``api2.realtor.ca`` -> ``realtor.ca``; ``www.example.co.uk`` ->
    ``example.co.uk``; ``alice.github.io`` -> ``alice.github.io``. Used to
    group a site's API host with its www host and to scope WAF cookies.
    Backed by ``_psl`` (a curated subset of multi-label public suffixes,
    NOT the full Mozilla PSL); an unlisted multi-label TLD degrades to the
    TLD+1 heuristic. Empty host returns unchanged.
    """
    if not host:
        return host
    return _psl.registrable_domain(host)


def cookie_domain_matches(cookie_domain: str, registrable: str) -> bool:
    """True if a cookie's Domain belongs to ``registrable`` (or a subdomain).

    Boundary-aware: ``realtor.ca`` and ``api2.realtor.ca`` match
    ``realtor.ca``; ``evil-realtor.ca`` does not.
    """
    d = (cookie_domain or "").lstrip(".").rstrip(".").lower()
    registrable = (registrable or "").rstrip(".").lower()
    return bool(registrable) and (
        d == registrable or d.endswith("." + registrable)
    )


def browser_cookie_matches_host(cookie_domain: str, host: str) -> bool:
    """Whether a Playwright cookie is allowed on ``host``.

    Chromium represents Domain cookies with a leading dot and host-only cookies
    without one. Preserve that distinction: a host-only cookie from
    ``www.example.com`` must not be promoted to ``api.example.com``, and a
    Domain cookie for ``.www.example.com`` does not cover that API sibling.

    A cookie with no domain fails closed. ``BrowserContext.cookies()`` always
    populates it, but ``browser_solver`` is a duck-typed extension point, and
    a custom solver's domain-less cookie must not be silently rebound to the
    target host and persisted under it.
    """

    if not cookie_domain:
        return False
    domain_cookie = cookie_domain.startswith(".")
    domain = cookie_domain.lstrip(".").rstrip(".").lower()
    host = (host or "").rstrip(".").lower()
    if not domain or not host:
        return False
    if not domain_cookie:
        return host == domain
    return host == domain or host.endswith("." + domain)


def _parse_cookie_name(raw: str) -> str | None:
    """Extract cookie name from a Set-Cookie header value."""
    eq = raw.find("=")
    if eq <= 0:
        return None
    return raw[:eq].strip()


def _parse_cookie_expires(raw: str) -> float:
    """Extract expiry timestamp from Set-Cookie, or 0 for session cookies."""
    lower = raw.lower()

    # max-age takes precedence over expires
    idx = lower.find("max-age=")
    if idx != -1:
        rest = raw[idx + 8 :]
        semi = rest.find(";")
        val = rest[:semi] if semi != -1 else rest
        try:
            return time.time() + max(0, int(val.strip()))
        except ValueError:
            pass

    # expires attribute
    idx = lower.find("expires=")
    if idx != -1:
        rest = raw[idx + 8 :]
        semi = rest.find(";")
        val = rest[:semi] if semi != -1 else rest
        try:
            dt = email.utils.parsedate_to_datetime(val.strip())
            return dt.timestamp()
        except (ValueError, TypeError):
            pass

    return 0.0


def _default_cookie_path(url: str) -> str:
    """Return RFC 6265's default-path for a cookie-setting request URL."""

    path = urlparse(url).path
    if not path or not path.startswith("/") or path.count("/") <= 1:
        return "/"
    return path.rsplit("/", 1)[0] or "/"


def _cookie_identity(entry: dict) -> tuple[str, str, str]:
    """Return the RFC cookie identity: name, domain, and path."""

    raw = str(entry.get("raw", ""))
    attributes: dict[str, str] = {}
    for part in raw.split(";")[1:]:
        key, separator, value = part.strip().partition("=")
        if separator:
            attributes[key.lower()] = value.strip()

    parsed = urlparse(str(entry.get("url", "")))
    domain = str(
        entry.get("domain")
        or attributes.get("domain")
        or parsed.hostname
        or ""
    ).lstrip(".").lower()
    path_value = entry.get("path")
    if path_value is None:
        path_value = attributes.get("path")
    path = str(path_value or "")
    if not path.startswith("/"):
        path = _default_cookie_path(str(entry.get("url", "")))
    return str(entry.get("name", "")), domain, path


def _numeric_timestamp(entry: dict, key: str) -> float:
    """Read a persisted timestamp without trusting cache-file JSON types."""

    try:
        return float(entry.get(key, 0))
    except (TypeError, ValueError):
        return 0.0


class CookieCache:
    """JSON-file-per-domain cookie cache with TTL and LRU eviction.

    Each domain gets a JSON file: {cache_dir}/{domain}.json
    Writes are atomic (temp file + rename) with per-domain threading
    locks to prevent lost-update races on concurrent save().
    """

    def __init__(
        self,
        cache_dir: str,
        max_entries: int = 50,
    ):
        self._cache_dir = Path(cache_dir)
        self._max_entries = max_entries
        self._sweep_counter = 0
        self._sweep_lock = threading.Lock()
        self._domain_locks: dict[str, threading.Lock] = {}
        self._lock_lock = threading.Lock()

    def _domain_path(self, domain: str) -> Path:
        safe = (
            domain.replace("/", "_")
            .replace("\\", "_")
            .replace(":", "_")
        )
        return self._cache_dir / f"{safe}.json"

    def _load_raw(self, domain: str) -> list[dict]:
        """Load entries from disk without TTL filtering."""
        path = self._domain_path(domain)
        if not path.exists():
            return []
        try:
            with open(path) as f:
                data = json.load(f)
            if not isinstance(data, list):
                logger.warning(
                    "Corrupt cookie file for %s, ignoring", domain
                )
                return []
            valid = [entry for entry in data if isinstance(entry, dict)]
            if len(valid) != len(data):
                logger.warning(
                    "Corrupt cookie entries for %s, ignoring invalid values",
                    domain,
                )
            return valid
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(
                "Failed to load cookies for %s: %s", domain, e
            )
            return []

    def load(self, domain: str) -> list[dict]:
        """Load non-expired cookies for a domain."""
        entries = self._load_raw(domain)
        now = time.time()
        valid = []
        for e in entries:
            expires = _numeric_timestamp(e, "expires")
            if expires == 0:
                # Session cookie (no max-age/expires) - skip, these
                # should not survive across process restarts.
                continue
            if expires > now:
                e["last_used"] = now
                valid.append(e)
        # Don't rewrite here to prune expired entries - that would race
        # with save() which holds the domain lock.  Expired entries are
        # cleaned up by save()'s TTL compaction and _sweep_expired().
        return valid

    def _get_domain_lock(self, domain: str) -> threading.Lock:
        # Lock by the actual filename, not the unsanitized caller input.
        # Domains such as IPv6 literals contain ":" and aliases such as
        # "a/b" collide after _domain_path() sanitization; sharing the path
        # must also mean sharing the lock.
        lock_key = self._domain_path(domain).name
        with self._lock_lock:
            if lock_key not in self._domain_locks:
                self._domain_locks[lock_key] = threading.Lock()
            return self._domain_locks[lock_key]

    def save(self, domain: str, cookies: list[dict]) -> None:
        """Save cookies with merge, TTL compaction, and LRU eviction."""
        if not cookies:
            return

        now = time.time()

        # Sweep stale domain files every ~10 saves
        do_sweep = False
        with self._sweep_lock:
            self._sweep_counter += 1
            if self._sweep_counter >= 10:
                self._sweep_counter = 0
                do_sweep = True
        if do_sweep:
            self._sweep_expired(now)

        with self._get_domain_lock(domain):
            existing = self._load_raw(domain)

            by_identity: dict[tuple[str, str, str], dict] = {}
            for e in existing:
                identity = _cookie_identity(e)
                if identity[0]:
                    by_identity[identity] = e

            for c in cookies:
                c.setdefault("last_used", now)
                identity = _cookie_identity(c)
                if identity[0]:
                    by_identity[identity] = c

            merged = list(by_identity.values())

            # TTL compaction - drop session cookies (expires=0) and expired
            merged = [
                e
                for e in merged
                if _numeric_timestamp(e, "expires") > now
            ]

            # LRU eviction
            if len(merged) > self._max_entries:
                merged.sort(
                    key=lambda c: _numeric_timestamp(c, "last_used")
                )
                evicted = len(merged) - self._max_entries
                merged = merged[evicted:]
                logger.warning(
                    "LRU evicted %d cookies for %s", evicted, domain
                )

            self._write_atomic(domain, merged)

    def save_from_headers(
        self, domain: str, raw_values: list, url: str
    ) -> None:
        """Parse Set-Cookie header bytes and save to cache."""
        cookies = []
        now = time.time()
        for raw in raw_values:
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8", errors="replace")
            else:
                raw = str(raw)
            name = _parse_cookie_name(raw)
            if not name:
                continue
            cookies.append(
                {
                    "name": name,
                    "raw": raw,
                    "url": url,
                    "expires": _parse_cookie_expires(raw),
                    "last_used": now,
                }
            )
        if cookies:
            self.save(domain, cookies)
            logger.debug(
                "Cached %d cookies for %s", len(cookies), domain
            )

    def clear(self, domain: str) -> None:
        """Delete cookie cache for a domain."""
        with self._get_domain_lock(domain):
            path = self._domain_path(domain)
            try:
                path.unlink(missing_ok=True)
            except OSError as e:
                logger.warning(
                    "Failed to clear cookies for %s: %s", domain, e
                )

    def list_domains(self) -> list[str]:
        """List all domains with cached cookies."""
        if not self._cache_dir.exists():
            return []
        return [p.stem for p in self._cache_dir.glob("*.json")]

    def _sweep_expired(self, now: float) -> None:
        """Delete domain files where all cookies have expired.

        Only inspects files not modified in the last 24 hours —
        recently-written files almost certainly have valid cookies.
        """
        if not self._cache_dir.exists():
            return
        stale_threshold = now - 86400  # 24 hours
        for path in self._cache_dir.glob("*.json"):
            with self._get_domain_lock(path.stem):
                try:
                    if path.stat().st_mtime > stale_threshold:
                        continue
                    with open(path) as f:
                        entries = json.load(f)
                    if not isinstance(entries, list) or not entries:
                        path.unlink(missing_ok=True)
                        continue
                    has_valid = any(
                        isinstance(e, dict)
                        and _numeric_timestamp(e, "expires") > now
                        for e in entries
                    )
                    if not has_valid:
                        path.unlink(missing_ok=True)
                        logger.debug(
                            "Swept expired cookie file: %s",
                            path.stem,
                        )
                except (json.JSONDecodeError, OSError):
                    pass

    def _write_atomic(self, domain: str, entries: list[dict]) -> None:
        """Atomic write: temp file + rename (same filesystem = atomic on POSIX).

        Cookie files hold WAF-clearance and auth tokens, so each file is
        written 0o600 (owner-only) and the cache dir is created 0o700, so
        other local users can neither read the values nor enumerate the
        cached domains.
        """
        # mode=0o700 only applies when wafer creates the dir; a pre-existing
        # dir the caller set up intentionally is left untouched.
        self._cache_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = self._domain_path(domain)
        fd, tmp_path = tempfile.mkstemp(
            dir=self._cache_dir, suffix=".tmp"
        )
        try:
            # mkstemp already creates 0o600; set it explicitly so the
            # owner-only guarantee survives any future change here (POSIX).
            if hasattr(os, "fchmod"):
                os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w") as f:
                json.dump(entries, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, path)
            if os.name != "nt":
                dir_flags = os.O_RDONLY
                if hasattr(os, "O_DIRECTORY"):
                    dir_flags |= os.O_DIRECTORY
                dir_fd = os.open(self._cache_dir, dir_flags)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
