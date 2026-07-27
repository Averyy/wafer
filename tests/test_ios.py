"""Tests for the wire-verified iOS Safari profile."""

import os
from unittest.mock import patch

import pytest
import wreq
from wreq.tls import (
    AlpnProtocol,
    CertificateCompressionAlgorithm,
    ExtensionType,
    KeyShare,
    TlsOptions,
    TlsVersion,
)

from wafer import AsyncSession, Profile, SyncSession
from wafer._base import BaseSession
from wafer._ios import (
    _ALPN_PROTOCOLS,
    _CERTIFICATE_COMPRESSION_ALGORITHMS,
    _CIPHER_LIST,
    _CIPHER_SUITES,
    _CURVES_LIST,
    _EXTENSION_PERMUTATION,
    _H2_CONNECTION_WINDOW_SIZE,
    _H2_INITIAL_WINDOW_SIZE,
    _IOS_RELEASE,
    _KEY_SHARES,
    _SIGNATURE_ALGORITHM_LIST,
    _SIGNATURE_ALGORITHMS,
    IOSSafariIdentity,
)

from .conftest import MockResponse, make_async_session, make_sync_session

_UA = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/26.5.2 Mobile/15E148 Safari/604.1"
)

_CIPHERS = (
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
_SIGNATURES = (
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
_EXTENSIONS = (
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
_JA3_SCRAPFLY = (
    "772,4866-4867-4865-49196-49195-52393-49200-49199-52392-49162-"
    "49161-49172-49171-157-156-53-47-49160-49170-10,"
    "0-23-65281-10-11-16-5-13-18-51-45-43-27,"
    "4588-29-23-24-25,0"
)
_H2 = "2:0;3:100;4:2097152;9:1|10420225|0|m,s,a,p"
# Documented in the wafer._ios module docstring; recomputed from the module's
# own constants by test_declared_vectors_reproduce_the_documented_fingerprints.
_JA3_HASH = "ecdf4f49dd59effc439639da29186671"
_JA4 = "t13d2013h2_a09f3c656075_7f0f34a4126d"

# IANA registry values. These tables are not trusted blindly: rebuilding the
# JA3 string from them must reproduce _JA3_SCRAPFLY exactly, which is what
# validates the mapping at the same time as the profile.
_CIPHER_ID = {
    "TLS_AES_128_GCM_SHA256": 4865,
    "TLS_AES_256_GCM_SHA384": 4866,
    "TLS_CHACHA20_POLY1305_SHA256": 4867,
    "ECDHE-ECDSA-AES128-GCM-SHA256": 49195,
    "ECDHE-ECDSA-AES256-GCM-SHA384": 49196,
    "ECDHE-RSA-AES128-GCM-SHA256": 49199,
    "ECDHE-RSA-AES256-GCM-SHA384": 49200,
    "ECDHE-ECDSA-CHACHA20-POLY1305": 52393,
    "ECDHE-RSA-CHACHA20-POLY1305": 52392,
    "ECDHE-ECDSA-AES128-SHA": 49161,
    "ECDHE-ECDSA-AES256-SHA": 49162,
    "ECDHE-RSA-AES128-SHA": 49171,
    "ECDHE-RSA-AES256-SHA": 49172,
    "AES128-GCM-SHA256": 156,
    "AES256-GCM-SHA384": 157,
    "AES128-SHA": 47,
    "AES256-SHA": 53,
    "ECDHE-ECDSA-DES-CBC3-SHA": 49160,
    "ECDHE-RSA-DES-CBC3-SHA": 49170,
    "DES-CBC3-SHA": 10,
}
# Keyed by repr(): wreq's TLS enums are not hashable.
_EXTENSION_ID = {
    "ExtensionType.SERVER_NAME": 0,
    "ExtensionType.STATUS_REQUEST": 5,
    "ExtensionType.SUPPORTED_GROUPS": 10,
    "ExtensionType.EC_POINT_FORMATS": 11,
    "ExtensionType.SIGNATURE_ALGORITHMS": 13,
    "ExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION": 16,
    "ExtensionType.CERTIFICATE_TIMESTAMP": 18,
    "ExtensionType.EXTENDED_MASTER_SECRET": 23,
    "ExtensionType.CERT_COMPRESSION": 27,
    "ExtensionType.SUPPORTED_VERSIONS": 43,
    "ExtensionType.PSK_KEY_EXCHANGE_MODES": 45,
    "ExtensionType.KEY_SHARE": 51,
    "ExtensionType.RENEGOTIATE": 65281,
}
_CURVE_ID = {
    "X25519MLKEM768": 4588,
    "X25519": 29,
    "P-256": 23,
    "P-384": 24,
    "P-521": 25,
}
_SIGALG_ID = {
    "ecdsa_secp256r1_sha256": 0x0403,
    "ecdsa_secp384r1_sha384": 0x0503,
    "rsa_pss_rsae_sha256": 0x0804,
    "rsa_pss_rsae_sha384": 0x0805,
    "rsa_pss_rsae_sha512": 0x0806,
    "rsa_pkcs1_sha256": 0x0401,
    "rsa_pkcs1_sha384": 0x0501,
    "rsa_pkcs1_sha512": 0x0601,
    "rsa_pkcs1_sha1": 0x0201,
}


class _UnusedNativeTransport:
    def __init__(self):
        self.calls = []

    def request(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        raise AssertionError("iOS Safari must not use native OpenSSL")


class TestIOSProfile:
    def test_value(self):
        assert Profile.IOS_SAFARI.value == "ios_safari"

    def test_exported_from_wafer(self):
        import wafer

        assert wafer.Profile.IOS_SAFARI is Profile.IOS_SAFARI


class TestIOSSafariIdentity:
    def test_captured_release_components(self):
        assert _IOS_RELEASE.safari_version == "26.5.2"
        assert _IOS_RELEASE.os_ua_version == "18_7"
        assert _IOS_RELEASE.mobile_build == "15E148"

    def test_user_agent_exact(self):
        assert IOSSafariIdentity().user_agent == _UA

    def test_client_headers_exact(self):
        headers = IOSSafariIdentity(locale="ca").client_headers()
        assert headers == {
            "Sec-Fetch-Dest": "document",
            "User-Agent": _UA,
            "Accept": (
                "text/html,application/xhtml+xml,"
                "application/xml;q=0.9,*/*;q=0.8"
            ),
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-Mode": "navigate",
            "Accept-Language": "en-CA,en-US;q=0.9,en;q=0.8",
            "Priority": "u=0, i",
            "Accept-Encoding": "gzip, deflate, br, zstd",
        }

    def test_us_locale(self):
        headers = IOSSafariIdentity(locale="us").client_headers()
        assert headers["Accept-Language"] == "en-US,en;q=0.9"

    def test_tls_options_construct(self):
        options = IOSSafariIdentity().tls_options()
        assert isinstance(options, TlsOptions)
        # Client construction validates wreq's BoringSSL cipher/sigalg names.
        with wreq.blocking.Client(tls_options=options) as client:
            assert isinstance(client, wreq.blocking.Client)

    def test_tls_options_kwargs_exact(self):
        with patch(
            "wafer._ios.TlsOptions",
            side_effect=lambda **kwargs: kwargs,
        ):
            options = IOSSafariIdentity().tls_options()
        assert options == {
            "cipher_list": ":".join(_CIPHERS),
            "preserve_tls13_cipher_list": True,
            "sigalgs_list": ":".join(_SIGNATURES),
            "min_tls_version": TlsVersion.TLS_1_2,
            "max_tls_version": TlsVersion.TLS_1_3,
            "alpn_protocols": (
                AlpnProtocol.HTTP2,
                AlpnProtocol.HTTP1,
            ),
            "certificate_compression_algorithms": (
                CertificateCompressionAlgorithm.ZLIB,
            ),
            "enable_ocsp_stapling": True,
            "enable_signed_cert_timestamps": True,
            "grease_enabled": True,
            "permute_extensions": True,
            "session_ticket": False,
            "curves_list": "X25519MLKEM768:X25519:P-256:P-384:P-521",
            "key_shares": (
                KeyShare.X25519_MLKEM768,
                KeyShare.X25519,
            ),
            "extension_permutation": _EXTENSIONS,
        }

    def test_captured_tls_sequences_exact(self):
        assert _CIPHER_SUITES == _CIPHERS
        assert _CIPHER_LIST == ":".join(_CIPHERS)
        assert _SIGNATURE_ALGORITHM_LIST == _SIGNATURES
        assert _SIGNATURE_ALGORITHMS == ":".join(_SIGNATURES)
        assert _ALPN_PROTOCOLS == (
            AlpnProtocol.HTTP2,
            AlpnProtocol.HTTP1,
        )
        assert _CERTIFICATE_COMPRESSION_ALGORITHMS == (
            CertificateCompressionAlgorithm.ZLIB,
        )
        assert _CURVES_LIST == "X25519MLKEM768:X25519:P-256:P-384:P-521"
        assert _KEY_SHARES == (
            KeyShare.X25519_MLKEM768,
            KeyShare.X25519,
        )
        assert _EXTENSION_PERMUTATION == _EXTENSIONS

    def test_declared_vectors_reproduce_the_documented_fingerprints(self):
        """Recompute JA3/JA4 from the module constants themselves.

        ``test_captured_tls_sequences_exact`` only proves the constants match
        a second literal copy; an edit applied to both would pass. Deriving
        the published hashes from the live constants is what actually pins
        the capture -- including the two shapes that look like transcription
        errors and are not: the duplicated ``rsa_pss_rsae_sha384`` (JA4_c
        matches only with it) and ``P-521`` in the curve list (JA3 matches
        only with it).
        """
        import hashlib

        ciphers = [_CIPHER_ID[name] for name in _CIPHER_SUITES]
        extensions = [_EXTENSION_ID[repr(ext)] for ext in _EXTENSION_PERMUTATION]
        sigalgs = [_SIGALG_ID[name] for name in _SIGNATURE_ALGORITHM_LIST]
        curves = [_CURVE_ID[name] for name in _CURVES_LIST.split(":")]

        cipher_field = "-".join(str(c) for c in ciphers)
        extension_field = "-".join(str(e) for e in extensions)
        curve_field = "-".join(str(c) for c in curves)

        # Rebuilding the recorded JA3 string proves the tables above and the
        # module constants agree with the capture.
        assert (
            f"772,{cipher_field},{extension_field},{curve_field},0"
            == _JA3_SCRAPFLY
        )

        # JA3 hashes the negotiated-version field as 771.
        assert (
            hashlib.md5(
                f"771,{cipher_field},{extension_field},{curve_field},0".encode()
            ).hexdigest()
            == _JA3_HASH
        )

        # JA4_a counts come from the same sequences.
        assert f"t13d{len(ciphers):02d}{len(extensions):02d}h2" == _JA4.split("_")[0]

        ja4_b = hashlib.sha256(
            ",".join(sorted(f"{c:04x}" for c in ciphers)).encode()
        ).hexdigest()[:12]
        # JA4_c drops SNI and ALPN, sorts extensions, and keeps sigalg order.
        ja4_c_exts = sorted(
            f"{e:04x}" for e in extensions if e not in (0x0000, 0x0010)
        )
        ja4_c = hashlib.sha256(
            (
                ",".join(ja4_c_exts)
                + "_"
                + ",".join(f"{s:04x}" for s in sigalgs)
            ).encode()
        ).hexdigest()[:12]
        assert f"t13d2013h2_{ja4_b}_{ja4_c}" == _JA4

    def test_http2_windows(self):
        assert _H2_CONNECTION_WINDOW_SIZE == 10485760
        assert _H2_INITIAL_WINDOW_SIZE == 2097152
        options = str(IOSSafariIdentity().http2_options())
        assert "initial_conn_window_size: 10485760" in options
        assert "initial_window_size: 2097152" in options
        assert "max_concurrent_streams: Some(100)" in options
        assert "enable_push: Some(false)" in options
        assert "no_rfc7540_priorities: Some(true)" in options

    def test_http2_options_kwargs_exact(self):
        with (
            patch(
                "wafer._ios.wreq.SettingsOrder",
                return_value="settings-order",
            ) as settings_order,
            patch(
                "wafer._ios.http2.PseudoOrder",
                return_value="pseudo-order",
            ) as pseudo_order,
            patch(
                "wafer._ios.wreq.Http2Options",
                side_effect=lambda **kwargs: kwargs,
            ),
        ):
            options = IOSSafariIdentity().http2_options()
        settings_order.assert_called_once_with(
            wreq.SettingId.ENABLE_PUSH,
            wreq.SettingId.MAX_CONCURRENT_STREAMS,
            wreq.SettingId.INITIAL_WINDOW_SIZE,
            wreq.SettingId.NO_RFC7540_PRIORITIES,
        )
        pseudo_order.assert_called_once_with(
            wreq.http2.PseudoId.METHOD,
            wreq.http2.PseudoId.SCHEME,
            wreq.http2.PseudoId.AUTHORITY,
            wreq.http2.PseudoId.PATH,
        )
        assert options == {
            "enable_push": False,
            "max_concurrent_streams": 100,
            "initial_window_size": 2097152,
            "initial_connection_window_size": 10485760,
            "no_rfc7540_priorities": True,
            "settings_order": "settings-order",
            "headers_pseudo_order": "pseudo-order",
        }


class TestIOSSafariSession:
    def test_custom_tls_identity(self):
        session = SyncSession(profile=Profile.IOS_SAFARI)
        try:
            assert session.emulation is None
            assert session._fingerprint is None
            assert session._ios_safari_identity is not None
            kwargs = session._build_client_kwargs()
            assert "tls_options" in kwargs
            assert "http2_options" in kwargs
            assert "emulation" not in kwargs
        finally:
            session._client.close()

    def test_mobile_safari_envelope(self):
        session = SyncSession(profile=Profile.IOS_SAFARI)
        try:
            env = session.fingerprint_envelope()
        finally:
            session._client.close()
        assert env["user_agent"] == _UA
        assert env["family"] == "safari"
        assert env["emulation"] == "ios_safari"
        assert env["is_mobile"] is True
        assert env["sec_ch_ua"] is None
        assert env["user_agent_data"] is None

    def test_custom_user_agent_envelope_matches_wire_headers(self):
        custom_ua = "custom-ios-client"
        session = SyncSession(
            profile=Profile.IOS_SAFARI,
            headers={"User-Agent": custom_ua},
        )
        try:
            env = session.fingerprint_envelope()
        finally:
            session._client.close()
        assert env["user_agent"] == custom_ua

    @pytest.mark.asyncio
    async def test_async_custom_tls_identity(self):
        session = AsyncSession(profile=Profile.IOS_SAFARI)
        try:
            assert session.emulation is None
            assert session._fingerprint is None
            assert session._ios_safari_identity is not None
            assert session.fingerprint_envelope()["is_mobile"] is True
            kwargs = session._build_client_kwargs()
            assert "tls_options" in kwargs
            assert "http2_options" in kwargs
            assert "emulation" not in kwargs
        finally:
            session._client.close()

    def test_rotation_keeps_identity(self):
        session = BaseSession(profile=Profile.IOS_SAFARI)
        identity = session._ios_safari_identity
        session._advance_rotation(4)
        assert session._ios_safari_identity is identity
        assert session._fingerprint is None

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"browser_solver": object()},
            {"solve_origin": "https://example.com/"},
        ],
    )
    def test_desktop_browser_solving_rejected(self, kwargs):
        with pytest.raises(ValueError, match="desktop Chromium"):
            BaseSession(profile=Profile.IOS_SAFARI, **kwargs)

    def test_native_openssl_fallback_disabled(self):
        session = BaseSession(profile=Profile.IOS_SAFARI)
        assert session._native_tls_usable() is False

    def test_sync_imperva_does_not_break_transport_identity(self):
        response = MockResponse(
            403,
            {"x-cdn": "Imperva", "content-type": "text/html"},
            "<html>incapsula</html>",
        )
        session, _ = make_sync_session(
            [response],
            profile=Profile.IOS_SAFARI,
            max_rotations=0,
        )
        native = _UnusedNativeTransport()
        session._native_tls = native

        result = session.get("https://example.com")

        assert result.status_code == 403
        assert result.challenge_type == "imperva"
        assert native.calls == []
        assert session._ios_safari_identity is not None

    @pytest.mark.asyncio
    async def test_async_imperva_does_not_break_transport_identity(self):
        response = MockResponse(
            403,
            {"x-cdn": "Imperva", "content-type": "text/html"},
            "<html>incapsula</html>",
        )
        session, _ = make_async_session(
            [response],
            profile=Profile.IOS_SAFARI,
            max_rotations=0,
        )
        native = _UnusedNativeTransport()
        session._native_tls = native

        result = await session.get("https://example.com")

        assert result.status_code == 403
        assert result.challenge_type == "imperva"
        assert native.calls == []
        assert session._ios_safari_identity is not None


@pytest.mark.live
@pytest.mark.skipif(
    os.environ.get("WAFER_LIVE") != "1",
    reason="live network test; set WAFER_LIVE=1 to run",
)
def test_live_ios_safari_wire_fingerprint():
    session = SyncSession(
        profile=Profile.IOS_SAFARI,
        max_retries=1,
        max_rotations=0,
    )
    try:
        data = session.get(
            "https://tools.scrapfly.io/api/fp/anything"
        ).json()
    finally:
        session._client.close()

    assert data["tls"]["ja3"] == _JA3_SCRAPFLY
    assert data["http2"]["fingerprint"] == _H2
    frames = data["http2"]["http2_frames"]
    assert frames[0]["settings_order"] == [2, 3, 4, 9]
    assert frames[1]["increment"] == 10420225
    assert frames[2]["ordered_headers_key"] == [
        ":method",
        ":scheme",
        ":authority",
        ":path",
        "sec-fetch-dest",
        "user-agent",
        "accept",
        "sec-fetch-site",
        "sec-fetch-mode",
        "accept-language",
        "priority",
        "accept-encoding",
    ]
    assert frames[2]["headers"]["user-agent"] == [_UA]
