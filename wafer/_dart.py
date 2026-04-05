"""Dart 3.11 identity -- TLS options and header profile.

Wire-verified against tls.peet.ws (2026-03-28). Dart 3.11.4 on macOS.
Produces requests matching:
  JA3 hash: 203503b7023848ab87b9836c336b8e81
  JA4: t13d1710_5b57614c22b0_78e6aca7449b

Uses wreq with custom TlsOptions (not Emulation). HTTP/1.1 is forced
by omitting ALPN (alpn_protocols=[]), NOT by http1_only (which injects
an ALPN extension). Dart's HttpClient (dart:io) uses BoringSSL but
never negotiates h2 and doesn't send ALPN. The fingerprint is shared
by all Flutter apps since they use the same Dart SDK TLS stack.
"""

import logging

from wreq.tls import (
    ExtensionType,
    TlsOptions,
    TlsVersion,
)

logger = logging.getLogger("wafer")

# Dart SDK version (major.minor only -- TLS doesn't include patch)
_DART_VERSION = "3.11"


class DartIdentity:
    """Dart 3.11 (dart:io) identity: TLS and header profile.

    Constructed once per session. Fixed for the session lifetime.
    Covers all Dart SDK 3.11.x and Flutter apps built with it.
    """

    def __init__(self):
        logger.debug("Dart identity: version=%s", _DART_VERSION)

    @property
    def user_agent(self) -> str:
        return f"Dart/{_DART_VERSION} (dart:io)"

    def tls_options(self) -> TlsOptions:
        """Wire-verified TLS config matching Dart 3.11 BoringSSL."""
        return TlsOptions(
            cipher_list=(
                "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:"
                "TLS_CHACHA20_POLY1305_SHA256:"
                "ECDHE-ECDSA-AES128-GCM-SHA256:"
                "ECDHE-RSA-AES128-GCM-SHA256:"
                "ECDHE-ECDSA-AES256-GCM-SHA384:"
                "ECDHE-RSA-AES256-GCM-SHA384:"
                "ECDHE-ECDSA-CHACHA20-POLY1305:"
                "ECDHE-RSA-CHACHA20-POLY1305:"
                "ECDHE-ECDSA-AES128-SHA:"
                "ECDHE-RSA-AES128-SHA:"
                "ECDHE-ECDSA-AES256-SHA:"
                "ECDHE-RSA-AES256-SHA:"
                "AES128-GCM-SHA256:AES256-GCM-SHA384:"
                "AES128-SHA:AES256-SHA"
            ),
            sigalgs_list=(
                "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:"
                "rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:"
                "rsa_pss_rsae_sha384:rsa_pkcs1_sha384:"
                "rsa_pss_rsae_sha512:rsa_pkcs1_sha512:"
                "rsa_pkcs1_sha1"
            ),
            min_tls_version=TlsVersion.TLS_1_2,
            max_tls_version=TlsVersion.TLS_1_3,
            # Dart doesn't send ALPN. Empty list suppresses the extension.
            # Do NOT use http1_only on Client -- that injects ALPN.
            alpn_protocols=[],
            grease_enabled=False,
            permute_extensions=False,
            curves_list="X25519:P-256:P-384",
            key_shares_limit=1,
            # Fixed extension order matching captured fingerprint
            extension_permutation=[
                ExtensionType.SERVER_NAME,
                ExtensionType.EXTENDED_MASTER_SECRET,
                ExtensionType.RENEGOTIATE,
                ExtensionType.SUPPORTED_GROUPS,
                ExtensionType.EC_POINT_FORMATS,
                ExtensionType.SESSION_TICKET,
                ExtensionType.SIGNATURE_ALGORITHMS,
                ExtensionType.KEY_SHARE,
                ExtensionType.PSK_KEY_EXCHANGE_MODES,
                ExtensionType.SUPPORTED_VERSIONS,
            ],
        )

    def client_headers(self) -> dict[str, str]:
        """Dart HttpClient headers (minimal -- no browser headers)."""
        return {
            "User-Agent": self.user_agent,
            "Accept-Encoding": "gzip",
        }
