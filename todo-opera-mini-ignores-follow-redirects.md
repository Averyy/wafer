# TODO: `Profile.OPERA_MINI` ignores `follow_redirects=False` (and the session's redirect settings)

**Owner:** wafer
**Status:** OPEN. Found from fetchaller on 2026-10-07, wafer 0.7.2. No wafer
code changed; this note is the hand-off.
**Reported by:** fetchaller

---

## Symptom

```python
AsyncSession(profile=Profile.OPERA_MINI, follow_redirects=False)
    .get("https://httpbin.org/redirect-to?url=https%3A%2F%2Fexample.com%2F&status_code=302")
```

returns **200** with `url=https://example.com/`. The redirect was followed.
The same call on the default profile returns **302** with
`location: https://example.com/`, as documented.

| profile | status | final URL | `location` |
|---|---|---|---|
| `Profile.OPERA_MINI` | 200 | `https://example.com/` | none |
| default | 302 | the httpbin URL | `https://example.com/` |

## Cause (from the source)

- `OperaMiniIdentity.__init__` (`wafer/_opera_mini.py:254`) builds its
  transport with `urllib.request.build_opener(HTTPSHandler(...),
  HTTPCookieProcessor(...))`. `build_opener` adds urllib's default handlers,
  including `HTTPRedirectHandler`, so every 3xx is followed by urllib.
- `OperaMiniIdentity.request()` takes only `url, headers, timeout, max_size`.
  The callers, `wafer/_async.py:1736` and `wafer/_sync.py:1545`, pass none of
  the session's `follow_redirects` or `max_redirects`, so both are ignored for
  this profile with no warning.

Two further things I read in the source but have **not tested**:

- `request()` takes no `proxy`/`resolve` either, so a session's `proxy=` and
  `resolve=` pins do not seem to reach Opera Mini requests. `build_opener` also
  adds `ProxyHandler()`, which reads proxies from the process environment
  instead.
- The redirect hops are urllib's, so whatever per-hop handling the wreq path
  applies (header stripping on cross-origin hops, and any hop validation) does
  not run on this path. urllib's redirect handler also accepts `ftp` targets.

## How fetchaller hit it

Google sometimes (about one response in thirty on 2026-10-07) returns result
links whose `q` is an opaque token (`/url?opi=..&q=CAES..&uoh=3&usg=..`)
instead of the destination. Resolving one needs a single hop with redirects
off. Asked on fetchaller's Opera Mini search session, the request followed the
302 and downloaded the result page itself (docs.python.org, 25 KB) instead of
returning the `Location`. fetchaller now resolves these on a separate
default-profile session with `follow_redirects=False`.

## Possible direction

Honour `follow_redirects`/`max_redirects` in `OperaMiniIdentity`: build the
opener without the default redirect handler (or with a subclass that stops on
the session's settings) and apply wafer's own hop logic. Either pass the
session's `proxy`/`resolve` through, or reject them for this profile at
construction so they cannot be silently ignored.

## Repro

```python
import asyncio, tempfile
from wafer import AsyncSession, Profile

URL = "https://httpbin.org/redirect-to?url=https%3A%2F%2Fexample.com%2F&status_code=302"

async def main():
    for profile in (Profile.OPERA_MINI, None):
        kw = {"profile": profile} if profile else {}
        s = AsyncSession(follow_redirects=False, max_rotations=0, cache_dir=tempfile.mkdtemp(), **kw)
        r = await s.get(URL, timeout=10)
        print(profile, r.status_code, r.url, r.headers.get("location"))

if __name__ == "__main__":
    asyncio.run(main())
```
