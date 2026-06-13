"""PSL-lite: a curated subset of multi-label public suffixes.

This is NOT the full Mozilla Public Suffix List (which is ~10k entries and
needs periodic refreshing). It is a small, hand-picked set of the common
multi-label suffixes that the naive "last two labels" TLD+1 heuristic gets
wrong - the ones a scraper actually hits: country second-level domains
(``co.uk``, ``com.au``) and a few popular hosting suffixes where every
subdomain is a separate owner (``github.io``).

It exists so that two unrelated sites under the same public suffix
(``a.co.uk`` vs ``b.co.uk``, ``alice.github.io`` vs ``bob.github.io``) are
treated as *different* registrable domains - for same-site classification
(``Sec-Fetch-Site``) and cookie-domain matching, where treating them as the
same site would over-share cookies or mislabel a cross-site request.

Curated subset, intentionally incomplete. A miss degrades gracefully to the
TLD+1 heuristic (the prior behavior); it never raises.
"""

# Multi-label public suffixes (each entry has 2+ labels). Bare TLDs like
# ``com`` / ``ca`` / ``io`` are handled by the fallback below and are NOT
# listed here. Keep this list focused on the frequent ones.
_MULTI_LABEL_SUFFIXES = frozenset({
    # United Kingdom
    "co.uk", "ac.uk", "gov.uk", "org.uk", "me.uk", "net.uk", "ltd.uk",
    "plc.uk", "sch.uk",
    # Australia
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
    # New Zealand
    "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz",
    # Japan
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
    # South Korea
    "co.kr", "or.kr", "ne.kr", "go.kr", "re.kr",
    # India
    "co.in", "net.in", "org.in", "gen.in", "firm.in", "gov.in", "ac.in",
    # Brazil
    "com.br", "net.br", "org.br", "gov.br", "edu.br",
    # Mexico
    "com.mx", "net.mx", "org.mx", "gob.mx", "edu.mx",
    # South Africa
    "co.za", "org.za", "net.za", "gov.za", "ac.za",
    # Other common country second-levels
    "com.cn", "net.cn", "org.cn", "gov.cn", "com.tw", "com.hk", "com.sg",
    "com.tr", "com.ar", "com.co", "com.pl", "co.il", "com.ua",
    # Popular hosting suffixes where each subdomain is a distinct owner
    "github.io", "gitlab.io", "pages.dev", "workers.dev", "vercel.app",
    "netlify.app", "herokuapp.com", "web.app", "firebaseapp.com",
    "s3.amazonaws.com", "cloudfront.net",
})


def public_suffix(host: str) -> str:
    """Longest matching public suffix of ``host`` (the part not registrable).

    Returns the multi-label suffix when one of the curated entries matches
    (e.g. ``co.uk`` for ``foo.co.uk``), otherwise the final single label
    (the bare TLD, e.g. ``com`` for ``foo.com``). Empty string for an empty
    host. Case-insensitive.
    """
    if not host:
        return ""
    h = host.lower().rstrip(".")
    labels = h.split(".")
    # Try the longest candidate suffixes first (3 labels then 2), so a
    # 3-label entry would win over a 2-label one if both were curated.
    for n in (3, 2):
        if len(labels) >= n:
            candidate = ".".join(labels[-n:])
            if candidate in _MULTI_LABEL_SUFFIXES:
                return candidate
    # No multi-label suffix matched: the public suffix is the bare TLD.
    return labels[-1]


def registrable_domain(host: str) -> str:
    """The registrable domain of ``host`` (public suffix + one more label).

    ``www.example.co.uk`` -> ``example.co.uk``; ``api.example.com`` ->
    ``example.com``; ``alice.github.io`` -> ``alice.github.io``. A bare
    public suffix (``co.uk``) or a host that *is* a single label returns
    unchanged - there is no registrable label above it. Empty host returns
    empty. Never raises.
    """
    if not host:
        return ""
    h = host.lower().rstrip(".")
    suffix = public_suffix(h)
    if h == suffix:
        # Host is itself a public suffix (e.g. ``co.uk``) - nothing to
        # register above it. Return as-is.
        return h
    suffix_labels = suffix.count(".") + 1
    labels = h.split(".")
    take = suffix_labels + 1
    if len(labels) < take:
        return h
    return ".".join(labels[-take:])


def same_site(a: str, b: str) -> bool:
    """True if hosts ``a`` and ``b`` share the same registrable domain.

    PSL-aware: ``a.co.uk`` and ``b.co.uk`` are NOT same-site (different
    registrable domains under the ``co.uk`` public suffix), while
    ``www.example.com`` and ``api.example.com`` are. Empty hosts are never
    same-site. Scheme/port are the caller's concern - this compares hosts
    only.
    """
    if not a or not b:
        return False
    ra = registrable_domain(a)
    rb = registrable_domain(b)
    # A bare public suffix has no registrable domain of its own; two such
    # (or a suffix vs a real domain) must never be judged same-site.
    if not ra or ra == public_suffix(ra):
        return False
    return ra == rb
