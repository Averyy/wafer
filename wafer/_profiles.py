"""HTTP-layer identity profiles, separate from TLS-layer Emulation."""

from enum import Enum


class Profile(Enum):
    """Named non-default client identities.

    Profiles select a coherent header and transport identity where a wreq
    Emulation alone is not the right abstraction.

    Chrome is the default (no profile needed). Profiles exist for
    non-Chrome HTTP identities that serve a specific purpose.

    OPERA_MINI bypasses wreq entirely — it uses Python's stdlib urllib
    with system OpenSSL for transport, matching real Opera Mini's
    server-side proxy architecture.
    """
    OPERA_MINI = "opera_mini"
    SAFARI = "safari"
    IOS_SAFARI = "ios_safari"
    DART = "dart"
