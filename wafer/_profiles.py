"""HTTP-layer identity profiles, separate from TLS-layer Emulation."""

from enum import Enum


class Profile(Enum):
    """HTTP-layer identity profiles.

    Profiles control HTTP headers (User-Agent, Accept, custom headers)
    independently of the TLS-layer Emulation.

    Chrome is the default (no profile needed). Profiles exist for
    non-Chrome HTTP identities that serve a specific purpose.

    OPERA_MINI bypasses rnet entirely — it uses Python's stdlib urllib
    with system OpenSSL for transport, matching real Opera Mini's
    server-side proxy architecture.
    """
    OPERA_MINI = "opera_mini"
    # Future profiles could include other proxy browsers, WebView
    # impersonation, Googlebot, etc. -- but only add them when there's
    # a real consumer with a real use case.
