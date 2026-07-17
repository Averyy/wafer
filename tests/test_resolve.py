"""Tests for the ``resolve=`` host->IP DNS-pinning passthrough.

fetchaller's SSRF guard resolves a hostname, verifies every IP is public,
then hands wafer a pre-validated host->IP map so wafer connects the socket
to exactly those IPs -closing the TOCTOU DNS-rebinding window between the
guard's check and wafer's connect. TLS SNI + cert validation still key on
the original hostname (so HTTPS keeps working), and the anti-detection
fingerprint is untouched.

The loopback tests prove socket-level pinning without external network: a
non-resolvable hostname (``pinned.invalid``) pinned to ``127.0.0.1`` reaches
a loopback server only if the socket honored the pin. The ``@live`` tests
prove the security-critical property -that the cert keys on the hostname,
not the pinned IP -against the real network.
"""

import http.client
import os
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from wafer import AsyncSession, SyncSession
from wafer._base import _canonical_host, _canonicalize_url_host
from wafer._native_tls import NativeTLSTransport

from .conftest import make_sync_session

# ---------------------------------------------------------------------------
# Loopback server fixture
# ---------------------------------------------------------------------------


def _start_loopback(host_records):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            host_records.append(self.headers.get("Host"))
            body = b'{"ok": true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    srv = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    return srv, thread


@pytest.fixture
def loopback():
    """Yield ``(port, host_records)`` for a loopback HTTP server.

    ``host_records`` collects the ``Host`` header of each handled request so
    a test can assert the socket pinned to the loopback IP while the request
    still addressed the original hostname.
    """
    host_records: list[str] = []
    srv, thread = _start_loopback(host_records)
    port = srv.server_address[1]
    try:
        yield port, host_records
    finally:
        srv.shutdown()
        thread.join(timeout=5)


# ---------------------------------------------------------------------------
# __init__ validation and normalization
# ---------------------------------------------------------------------------


class TestResolveInit:
    def test_default_is_empty(self):
        assert SyncSession()._resolve == {}

    def test_lowercases_host_keys(self):
        s = SyncSession(resolve={"Example.COM": ["127.0.0.1"]})
        assert s._resolve == {"example.com": ["127.0.0.1"]}

    def test_strips_whitespace_from_host(self):
        s = SyncSession(resolve={"  example.com  ": ["127.0.0.1"]})
        assert "example.com" in s._resolve

    def test_multiple_ips_preserved_in_order(self):
        s = SyncSession(resolve={"example.com": ["10.0.0.1", "10.0.0.2"]})
        assert s._resolve["example.com"] == ["10.0.0.1", "10.0.0.2"]

    def test_ipv6_accepted(self):
        s = SyncSession(resolve={"example.com": ["::1"]})
        assert s._resolve["example.com"] == ["::1"]

    def test_empty_ip_list_raises(self):
        # A listed host with no IPs would silently fall through to real DNS,
        # reopening the exact hole the caller meant to close: raise instead.
        with pytest.raises(ValueError):
            SyncSession(resolve={"example.com": []})

    def test_blank_host_raises(self):
        with pytest.raises(ValueError):
            SyncSession(resolve={"   ": ["127.0.0.1"]})

    def test_invalid_ip_raises_up_front(self):
        # Validated at construction so a later _rebuild_client (fingerprint
        # rotation) can never raise on a bad address mid-flight.
        with pytest.raises(ValueError):
            SyncSession(resolve={"example.com": ["not-an-ip"]})

    def test_resolve_with_proxy_raises(self):
        # A proxy resolves the target host, so the pin would be silently
        # voided: refuse the unsatisfiable SSRF contract loudly.
        with pytest.raises(ValueError):
            SyncSession(
                resolve={"example.com": ["127.0.0.1"]},
                proxy="http://proxy.example:8080",
            )

    def test_trailing_dot_stripped_from_key(self):
        # A trailing-dot FQDN denotes the same host; the key is canonicalized
        # so a request to either form matches the pin.
        s = SyncSession(resolve={"Example.COM.": ["127.0.0.1"]})
        assert s._resolve == {"example.com": ["127.0.0.1"]}

    def test_generator_addrs_empty_still_raises(self):
        # A single-use iterable must not slip past the empty-list guard and
        # store [] (which would silently fall through to real DNS).
        with pytest.raises(ValueError):
            SyncSession(resolve={"example.com": (a for a in [])})


class TestCanonicalHost:
    def test_canonical_host_lowercases_and_strips(self):
        assert _canonical_host("  Example.COM.  ") == "example.com"

    def test_idn_folded_to_punycode(self):
        # wreq sends punycode on the wire, so keys/lookups fold to it too.
        assert _canonical_host("MÜNCHEN.invalid") == "xn--mnchen-3ya.invalid"

    def test_already_punycode_not_double_encoded(self):
        assert (
            _canonical_host("xn--mnchen-3ya.invalid")
            == "xn--mnchen-3ya.invalid"
        )

    def test_underscore_host_falls_back_to_lowercase(self):
        # The IDNA codec rejects underscores; fall back, don't crash.
        assert _canonical_host("Foo_Bar.example") == "foo_bar.example"

    def test_url_host_lowercased_preserving_rest(self):
        assert (
            _canonicalize_url_host("http://PINNED.Invalid:8080/P?q=A#F")
            == "http://pinned.invalid:8080/P?q=A#F"
        )

    def test_url_trailing_dot_stripped(self):
        assert (
            _canonicalize_url_host("http://Example.COM./path")
            == "http://example.com/path"
        )

    def test_url_userinfo_and_port_preserved(self):
        # Only the host is touched; userinfo (incl. its case) and port stay.
        assert (
            _canonicalize_url_host("http://User:Pw@HOST.COM:8080/x")
            == "http://User:Pw@host.com:8080/x"
        )

    def test_url_ipv6_literal_untouched(self):
        assert (
            _canonicalize_url_host("http://[::1]:9/x") == "http://[::1]:9/x"
        )

    def test_url_already_canonical_unchanged(self):
        url = "https://already.lower/path?q=1"
        assert _canonicalize_url_host(url) == url


# ---------------------------------------------------------------------------
# Phase 1: wreq-path passthrough (_build_client_kwargs)
# ---------------------------------------------------------------------------


class TestBuildClientKwargs:
    def test_dns_options_injected_when_resolve_set(self):
        from wreq import DnsOptions

        session, _ = make_sync_session(
            [], resolve={"example.com": ["127.0.0.1"]}
        )
        kwargs = session._build_client_kwargs()
        assert isinstance(kwargs.get("dns_options"), DnsOptions)

    def test_dns_options_absent_without_resolve(self):
        session, _ = make_sync_session([])
        assert "dns_options" not in session._build_client_kwargs()

    def test_survives_fingerprint_rotation(self):
        # _build_client_kwargs runs on every _rebuild_client(), so the pin is
        # re-injected after rotation for free.
        session, _ = make_sync_session(
            [], resolve={"example.com": ["127.0.0.1"]}
        )
        session._fingerprint.rotate()
        assert "dns_options" in session._build_client_kwargs()

    def test_coexists_with_fingerprint(self):
        # dns_options is orthogonal to the emulation/TLS fingerprint.
        session, _ = make_sync_session(
            [], resolve={"example.com": ["127.0.0.1"]}
        )
        kwargs = session._build_client_kwargs()
        assert "emulation" in kwargs
        assert "dns_options" in kwargs


class TestBuildClientKwargsLoopback:
    async def test_async_wreq_path_pins_to_loopback(self, loopback):
        # pinned.invalid never resolves via real DNS, so a 200 proves the
        # socket connected to the pinned 127.0.0.1 on the real wreq client.
        port, host_records = loopback
        s = AsyncSession(resolve={"pinned.invalid": ["127.0.0.1"]})
        resp = await s.get(f"http://pinned.invalid:{port}/")
        assert resp.status_code == 200
        assert resp.json()["ok"] is True
        assert host_records == [f"pinned.invalid:{port}"]

    def test_sync_wreq_path_pins_to_loopback(self, loopback):
        port, host_records = loopback
        s = SyncSession(resolve={"pinned.invalid": ["127.0.0.1"]})
        resp = s.get(f"http://pinned.invalid:{port}/")
        assert resp.status_code == 200
        assert host_records == [f"pinned.invalid:{port}"]

    async def test_async_wreq_path_pins_mixed_case_host(self, loopback):
        # Regression: wreq's DnsOptions matches the URL host verbatim, so a
        # mixed-case request host must be canonicalized or it bypasses the pin
        # and falls through to real DNS -reopening the SSRF-rebinding window.
        port, _ = loopback
        s = AsyncSession(
            resolve={"pinned.invalid": ["127.0.0.1"]},
            max_retries=1,
            max_rotations=0,
        )
        resp = await s.get(f"http://PINNED.INVALID:{port}/")
        assert resp.status_code == 200

    def test_sync_wreq_path_pins_trailing_dot_host(self, loopback):
        port, _ = loopback
        s = SyncSession(
            resolve={"pinned.invalid": ["127.0.0.1"]},
            max_retries=1,
            max_rotations=0,
        )
        resp = s.get(f"http://pinned.invalid.:{port}/")
        assert resp.status_code == 200

    async def test_async_wreq_path_pins_idn_host(self, loopback):
        # An IDN pin key must be honored whether the request uses the Unicode
        # or the punycode form (wreq matches punycode on the wire).
        port, _ = loopback
        s = AsyncSession(
            resolve={"münchen.invalid": ["127.0.0.1"]},
            max_retries=1,
            max_rotations=0,
        )
        for host in ("münchen.invalid", "xn--mnchen-3ya.invalid"):
            resp = await s.get(f"http://{host}:{port}/")
            assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Phase 2: native-TLS path pinning (_pin_socket)
# ---------------------------------------------------------------------------


class TestNativePinSocket:
    def test_noop_for_unlisted_host(self):
        t = NativeTLSTransport(resolve={"example.com": ["10.0.0.1"]})
        conn = http.client.HTTPConnection("other.com", 80)
        orig = conn._create_connection
        t._pin_socket(conn, "other.com", 80)
        assert conn._create_connection is orig

    def test_noop_when_no_resolve_map(self):
        t = NativeTLSTransport()
        conn = http.client.HTTPSConnection("example.com", 443)
        orig = conn._create_connection
        t._pin_socket(conn, "example.com", 443)
        assert conn._create_connection is orig

    def test_shadows_create_connection_for_listed_host(self):
        t = NativeTLSTransport(resolve={"example.com": ["10.0.0.1"]})
        conn = http.client.HTTPSConnection("example.com", 443)
        orig = conn._create_connection
        t._pin_socket(conn, "example.com", 443)
        # Socket connect is redirected...
        assert conn._create_connection is not orig
        # ...but SNI/cert still key on the hostname.
        assert conn.host == "example.com"

    def test_lookup_is_case_insensitive(self):
        t = NativeTLSTransport(resolve={"example.com": ["10.0.0.1"]})
        conn = http.client.HTTPSConnection("EXAMPLE.com", 443)
        orig = conn._create_connection
        t._pin_socket(conn, "EXAMPLE.com", 443)
        assert conn._create_connection is not orig


class TestNativePinLoopback:
    def test_native_path_pins_and_keeps_host_header(self, loopback):
        port, host_records = loopback
        t = NativeTLSTransport(resolve={"pinned.invalid": ["127.0.0.1"]})
        status, headers, body, url, cookies = t.request(
            "GET", f"http://pinned.invalid:{port}/", {"Accept": "*/*"}
        )
        assert status == 200
        assert body == b'{"ok": true}'
        # Socket connected to the pinned loopback IP (pinned.invalid never
        # resolves), while the Host header still carries the hostname.
        assert host_records == [f"pinned.invalid:{port}"]

    def test_native_path_unpinned_host_still_works(self, loopback):
        # A transport with a resolve map that does not cover the requested
        # host must fall through to normal resolution.
        port, host_records = loopback
        t = NativeTLSTransport(resolve={"other.invalid": ["203.0.113.9"]})
        status, _, body, _, _ = t.request(
            "GET", f"http://127.0.0.1:{port}/", {"Accept": "*/*"}
        )
        assert status == 200
        assert body == b'{"ok": true}'

    def test_native_path_pins_mixed_case_host(self, loopback):
        port, host_records = loopback
        t = NativeTLSTransport(resolve={"pinned.invalid": ["127.0.0.1"]})
        status, _, body, _, _ = t.request(
            "GET", f"http://PINNED.Invalid:{port}/", {"Accept": "*/*"}
        )
        assert status == 200
        assert body == b'{"ok": true}'

    def test_native_transport_canonicalizes_its_own_keys(self, loopback):
        # Defense-in-depth: constructing the transport directly with a
        # non-canonical key must still honor the pin (keys are canonicalized
        # in __init__, not just at lookup), so it can't fall open to real DNS.
        port, _ = loopback
        t = NativeTLSTransport(resolve={"PINNED.Invalid.": ["127.0.0.1"]})
        status, _, body, _, _ = t.request(
            "GET", f"http://pinned.invalid:{port}/", {"Accept": "*/*"}
        )
        assert status == 200
        assert body == b'{"ok": true}'

    def test_native_path_fails_over_across_ips(self, loopback):
        # A dead first IP must fail over to the next, matching the wreq path
        # (192.0.2.1 is TEST-NET-1, guaranteed unroutable).
        port, _ = loopback
        t = NativeTLSTransport(
            resolve={"pinned.invalid": ["192.0.2.1", "127.0.0.1"]}
        )
        status, _, body, _, _ = t.request(
            "GET",
            f"http://pinned.invalid:{port}/",
            {"Accept": "*/*"},
            timeout=8,
        )
        assert status == 200


# ---------------------------------------------------------------------------
# Live: cert keys on the hostname, not the pinned IP (the security property)
# ---------------------------------------------------------------------------


@pytest.mark.live
@pytest.mark.skipif(
    os.environ.get("WAFER_LIVE") != "1",
    reason="live network test; set WAFER_LIVE=1 to run",
)
class TestResolveLive:
    def test_https_real_ip_succeeds_wreq(self):
        ip = socket.gethostbyname("example.com")
        s = SyncSession(resolve={"example.com": [ip]})
        resp = s.get("https://example.com/")
        assert resp.status_code == 200

    def test_mixed_case_url_honors_pin_wreq(self):
        # Regression for the case-sensitivity fail-open: a mixed-case request
        # host pinned to a WRONG-cert IP must fail TLS. Before the fix it
        # returned 200 via real DNS (pin bypassed).
        gh_ip = socket.gethostbyname("github.com")
        s = SyncSession(
            resolve={"example.com": [gh_ip]},
            max_retries=1,
            max_rotations=0,
        )
        with pytest.raises(Exception):
            s.get("https://EXAMPLE.COM/")

    def test_https_cert_keys_on_hostname_wreq(self):
        # github.com's cert does not cover example.com and github is not on
        # example.com's anycast fabric, so pinning example.com there must
        # fail TLS -proving validation keys on the hostname, not the IP.
        gh_ip = socket.gethostbyname("github.com")
        s = SyncSession(
            resolve={"example.com": [gh_ip]},
            max_retries=1,
            max_rotations=0,
        )
        with pytest.raises(Exception):
            s.get("https://example.com/")

    def test_https_cert_keys_on_hostname_native(self):
        gh_ip = socket.gethostbyname("github.com")
        t = NativeTLSTransport(resolve={"example.com": [gh_ip]})
        with pytest.raises(Exception):
            t.request(
                "GET",
                "https://example.com/",
                {"Accept": "*/*", "User-Agent": "curl/8"},
                timeout=8,
            )
