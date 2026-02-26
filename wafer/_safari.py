"""Safari 26 identity — TLS options, H2 options, and header profile.

Wire-verified against real Safari 26.2/26.3 on M3/M4 hardware (2026-02-23).
Produces requests matching JA4 t13d1414h2_ecfee8bf6ab3_bc9a4605e104 and
H2 akamai_fingerprint 2:0;3:100;4:6291456;9:1|8290305|0|m,s,a,p.

Uses rnet with custom TlsOptions (not Emulation). TlsOptions overrides
Emulation entirely — they cannot be combined.
"""

import logging
import random

import rnet
from rnet import http2
from rnet.tls import (
    AlpnProtocol,
    CertificateCompressionAlgorithm,
    ExtensionType,
    TlsOptions,
    TlsVersion,
)

logger = logging.getLogger("wafer")

# Safari versions we impersonate (weighted toward latest)
_VERSIONS = ["26.2", "26.3"]
_VERSION_WEIGHTS = [0.3, 0.7]


class SafariIdentity:
    """Safari 26 M3/M4 identity: TLS, H2, and header profile.

    Constructed once per session. Version and locale are fixed for the
    session lifetime (like a real browser instance).
    """

    def __init__(self, locale: str = "us"):
        self._locale = locale
        self._version = random.choices(
            _VERSIONS, weights=_VERSION_WEIGHTS, k=1
        )[0]
        logger.debug(
            "Safari identity: version=%s, locale=%s",
            self._version, self._locale,
        )

    @property
    def user_agent(self) -> str:
        return (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/605.1.15 (KHTML, like Gecko) "
            f"Version/{self._version} Safari/605.1.15"
        )

    def tls_options(self) -> TlsOptions:
        """Wire-verified TLS config matching Safari M3/M4."""
        return TlsOptions(
            cipher_list=(
                "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:"
                "TLS_CHACHA20_POLY1305_SHA256:"
                "ECDHE-ECDSA-AES128-GCM-SHA256:"
                "ECDHE-RSA-AES128-GCM-SHA256:"
                "ECDHE-ECDSA-AES256-GCM-SHA384:"
                "ECDHE-RSA-AES256-GCM-SHA384:"
                "ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:"
                "AES128-GCM-SHA256:AES256-GCM-SHA384:"
                "AES128-SHA:AES256-SHA:DES-CBC3-SHA"
            ),
            sigalgs_list=(
                "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:"
                "rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:"
                "rsa_pss_rsae_sha384:rsa_pkcs1_sha384:"
                "rsa_pss_rsae_sha512:rsa_pkcs1_sha512"
            ),
            min_tls_version=TlsVersion.TLS_1_2,
            max_tls_version=TlsVersion.TLS_1_3,
            alpn_protocols=[AlpnProtocol.HTTP2, AlpnProtocol.HTTP1],
            certificate_compression_algorithms=[
                CertificateCompressionAlgorithm.ZLIB,
            ],
            enable_ocsp_stapling=True,
            enable_signed_cert_timestamps=True,
            grease_enabled=True,
            permute_extensions=True,
            curves_list="X25519MLKEM768:X25519:P-256:P-384",
            key_shares_limit=2,
            extension_permutation=[
                ExtensionType.SIGNATURE_ALGORITHMS,
                ExtensionType.EXTENDED_MASTER_SECRET,
                ExtensionType.KEY_SHARE,
                ExtensionType.EC_POINT_FORMATS,
                ExtensionType.SUPPORTED_GROUPS,
                ExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
                ExtensionType.CERT_COMPRESSION,
                ExtensionType.SUPPORTED_VERSIONS,
                ExtensionType.STATUS_REQUEST,
                ExtensionType.SESSION_TICKET,
                ExtensionType.SERVER_NAME,
                ExtensionType.RENEGOTIATE,
                ExtensionType.CERTIFICATE_TIMESTAMP,
                ExtensionType.PSK_KEY_EXCHANGE_MODES,
            ],
        )

    def http2_options(self) -> rnet.Http2Options:
        """Wire-verified H2 config matching Safari M3/M4."""
        so = rnet.SettingsOrder(
            rnet.SettingId.ENABLE_PUSH,
            rnet.SettingId.MAX_CONCURRENT_STREAMS,
            rnet.SettingId.INITIAL_WINDOW_SIZE,
            rnet.SettingId.NO_RFC7540_PRIORITIES,
        )
        po = http2.PseudoOrder(
            http2.PseudoId.METHOD,
            http2.PseudoId.SCHEME,
            http2.PseudoId.AUTHORITY,
            http2.PseudoId.PATH,
        )
        return rnet.Http2Options(
            enable_push=False,
            max_concurrent_streams=100,
            initial_window_size=6291456,
            initial_connection_window_size=8355840,  # 8290305 + 65535
            no_rfc7540_priorities=True,
            settings_order=so,
            headers_pseudo_order=po,
        )

    def client_headers(self) -> dict[str, str]:
        """Safari-specific headers (set at rnet.Client level).

        Safari omits: sec-ch-ua (all variants), Sec-Fetch-User,
        Cache-Control, Upgrade-Insecure-Requests.
        """
        if self._locale == "ca":
            accept_language = "en-CA,en-US;q=0.9,en;q=0.8"
        else:
            accept_language = "en-US,en;q=0.9"

        if self._version >= "26.3":
            accept_encoding = "gzip, deflate, br, zstd"
        else:
            accept_encoding = "gzip, deflate, br"

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
            "Accept-Encoding": accept_encoding,
        }
