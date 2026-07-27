"""iOS Safari 26.5.2 identity — TLS, H2, and HTTP header profile.

Wire-verified against a real iPhone running Safari 26.5.2 (2026-07-26).
Produces JA3 ecdf4f49dd59effc439639da29186671, JA4
t13d2013h2_a09f3c656075_7f0f34a4126d, and H2 akamai_fingerprint
2:0;3:100;4:2097152;9:1|10420225|0|m,s,a,p.

That JA3 hash is the standard form, over a ``771`` version field.
tools.scrapfly.io builds the same cipher/extension/curve string with ``772``
and so reports digest ce959540f5d4be9d6ad5c8298de41113; the two agree on every
field that describes the ClientHello. Compare the string, not the digest,
across tools.

The apparently mismatched ``CPU iPhone OS 18_7`` and ``Version/26.5.2`` UA
tokens are what the real browser sent. Apple freezes UA components across OS
releases, so they must not be normalized to the marketing OS version.

Two shapes below look like transcription errors and are not: the duplicated
``rsa_pss_rsae_sha384`` (JA4_c reproduces only with it) and ``P-521`` in the
curve list (JA3 reproduces only with it). See the fingerprint-recomputation
test in tests/test_ios.py before editing either.
"""

import logging
from dataclasses import dataclass

import wreq
from wreq import http2
from wreq.tls import (
    AlpnProtocol,
    CertificateCompressionAlgorithm,
    ExtensionType,
    KeyShare,
    TlsOptions,
    TlsVersion,
)

logger = logging.getLogger("wafer")


@dataclass(frozen=True)
class IOSRelease:
    """UA components observed together in one real iOS Safari capture."""

    safari_version: str
    os_ua_version: str
    mobile_build: str


_IOS_RELEASE = IOSRelease(
    safari_version="26.5.2",
    os_ua_version="18_7",
    mobile_build="15E148",
)

_CIPHER_SUITES = (
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_GCM_SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-RSA-CHACHA20-POLY1305",
    "ECDHE-ECDSA-AES256-SHA",
    "ECDHE-ECDSA-AES128-SHA",
    "ECDHE-RSA-AES256-SHA",
    "ECDHE-RSA-AES128-SHA",
    "AES256-GCM-SHA384",
    "AES128-GCM-SHA256",
    "AES256-SHA",
    "AES128-SHA",
    "ECDHE-ECDSA-DES-CBC3-SHA",
    "ECDHE-RSA-DES-CBC3-SHA",
    "DES-CBC3-SHA",
)
_CIPHER_LIST = ":".join(_CIPHER_SUITES)

_SIGNATURE_ALGORITHM_LIST = (
    "ecdsa_secp256r1_sha256",
    "rsa_pss_rsae_sha256",
    "rsa_pkcs1_sha256",
    "ecdsa_secp384r1_sha384",
    "rsa_pss_rsae_sha384",
    "rsa_pss_rsae_sha384",
    "rsa_pkcs1_sha384",
    "rsa_pss_rsae_sha512",
    "rsa_pkcs1_sha512",
    "rsa_pkcs1_sha1",
)
_SIGNATURE_ALGORITHMS = ":".join(_SIGNATURE_ALGORITHM_LIST)

_ALPN_PROTOCOLS = (AlpnProtocol.HTTP2, AlpnProtocol.HTTP1)
_CERTIFICATE_COMPRESSION_ALGORITHMS = (
    CertificateCompressionAlgorithm.ZLIB,
)
_CURVES_LIST = "X25519MLKEM768:X25519:P-256:P-384:P-521"
_KEY_SHARES = (KeyShare.X25519_MLKEM768, KeyShare.X25519)
_EXTENSION_PERMUTATION = (
    ExtensionType.SERVER_NAME,
    ExtensionType.EXTENDED_MASTER_SECRET,
    ExtensionType.RENEGOTIATE,
    ExtensionType.SUPPORTED_GROUPS,
    ExtensionType.EC_POINT_FORMATS,
    ExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
    ExtensionType.STATUS_REQUEST,
    ExtensionType.SIGNATURE_ALGORITHMS,
    ExtensionType.CERTIFICATE_TIMESTAMP,
    ExtensionType.KEY_SHARE,
    ExtensionType.PSK_KEY_EXCHANGE_MODES,
    ExtensionType.SUPPORTED_VERSIONS,
    ExtensionType.CERT_COMPRESSION,
)
_H2_INITIAL_WINDOW_SIZE = 2097152
_H2_CONNECTION_WINDOW_SIZE = 10485760


class IOSSafariIdentity:
    """A wire-verified iPhone Safari identity, fixed for a session."""

    def __init__(self, locale: str = "us"):
        self._locale = locale
        self._release = _IOS_RELEASE
        logger.debug(
            "iOS Safari identity: version=%s, os_ua=%s, locale=%s",
            self._release.safari_version,
            self._release.os_ua_version,
            self._locale,
        )

    @property
    def release(self) -> IOSRelease:
        return self._release

    @property
    def user_agent(self) -> str:
        return (
            "Mozilla/5.0 (iPhone; CPU iPhone OS "
            f"{self._release.os_ua_version} like Mac OS X) "
            "AppleWebKit/605.1.15 (KHTML, like Gecko) "
            f"Version/{self._release.safari_version} "
            f"Mobile/{self._release.mobile_build} Safari/604.1"
        )

    def tls_options(self) -> TlsOptions:
        """Return the TLS ClientHello configuration from the real capture."""
        return TlsOptions(
            cipher_list=_CIPHER_LIST,
            preserve_tls13_cipher_list=True,
            sigalgs_list=_SIGNATURE_ALGORITHMS,
            min_tls_version=TlsVersion.TLS_1_2,
            max_tls_version=TlsVersion.TLS_1_3,
            alpn_protocols=_ALPN_PROTOCOLS,
            certificate_compression_algorithms=(
                _CERTIFICATE_COMPRESSION_ALGORITHMS
            ),
            enable_ocsp_stapling=True,
            enable_signed_cert_timestamps=True,
            grease_enabled=True,
            permute_extensions=True,
            session_ticket=False,
            curves_list=_CURVES_LIST,
            key_shares=_KEY_SHARES,
            extension_permutation=_EXTENSION_PERMUTATION,
        )

    def http2_options(self) -> wreq.Http2Options:
        """Return the HTTP/2 settings and flow-control windows captured."""
        settings_order = wreq.SettingsOrder(
            wreq.SettingId.ENABLE_PUSH,
            wreq.SettingId.MAX_CONCURRENT_STREAMS,
            wreq.SettingId.INITIAL_WINDOW_SIZE,
            wreq.SettingId.NO_RFC7540_PRIORITIES,
        )
        pseudo_order = http2.PseudoOrder(
            http2.PseudoId.METHOD,
            http2.PseudoId.SCHEME,
            http2.PseudoId.AUTHORITY,
            http2.PseudoId.PATH,
        )
        return wreq.Http2Options(
            enable_push=False,
            max_concurrent_streams=100,
            initial_window_size=_H2_INITIAL_WINDOW_SIZE,
            # The capture reports WINDOW_UPDATE increment 10420225; wreq
            # accepts the resulting total connection window.
            initial_connection_window_size=_H2_CONNECTION_WINDOW_SIZE,
            no_rfc7540_priorities=True,
            settings_order=settings_order,
            headers_pseudo_order=pseudo_order,
        )

    def client_headers(self) -> dict[str, str]:
        """Return the measured iOS Safari top-level navigation envelope."""
        if self._locale == "ca":
            accept_language = "en-CA,en-US;q=0.9,en;q=0.8"
        else:
            accept_language = "en-US,en;q=0.9"

        return {
            "Sec-Fetch-Dest": "document",
            "User-Agent": self.user_agent,
            "Accept": (
                "text/html,application/xhtml+xml,"
                "application/xml;q=0.9,*/*;q=0.8"
            ),
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-Mode": "navigate",
            "Accept-Language": accept_language,
            "Priority": "u=0, i",
            "Accept-Encoding": "gzip, deflate, br, zstd",
        }
