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

logger = logging.getLogger("wafer")


def extract_domain(url: str) -> str | None:
    """Extract hostname from a URL."""
    return urlparse(url).hostname


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
            return data
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
            expires = e.get("expires", 0)
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
        with self._lock_lock:
            if domain not in self._domain_locks:
                self._domain_locks[domain] = threading.Lock()
            return self._domain_locks[domain]

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

            by_name: dict[str, dict] = {}
            for e in existing:
                name = e.get("name", "")
                if name:
                    by_name[name] = e

            for c in cookies:
                c.setdefault("last_used", now)
                name = c.get("name", "")
                if name:
                    by_name[name] = c

            merged = list(by_name.values())

            # TTL compaction - drop session cookies (expires=0) and expired
            merged = [
                e
                for e in merged
                if e.get("expires", 0) > now
            ]

            # LRU eviction
            if len(merged) > self._max_entries:
                merged.sort(key=lambda c: c.get("last_used", 0))
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
            try:
                if path.stat().st_mtime > stale_threshold:
                    continue
                with open(path) as f:
                    entries = json.load(f)
                if not isinstance(entries, list) or not entries:
                    path.unlink(missing_ok=True)
                    continue
                has_valid = any(
                    e.get("expires", 0) > now
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
        """Atomic write: temp file + rename (same filesystem = atomic on POSIX)."""
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        path = self._domain_path(domain)
        fd, tmp_path = tempfile.mkstemp(
            dir=self._cache_dir, suffix=".tmp"
        )
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(entries, f, indent=2)
            os.rename(tmp_path, path)
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
