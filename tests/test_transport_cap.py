"""max_response_size enforcement on the non-wreq transports.

The wreq path's cap is covered in test_max_response_size.py. This module
exercises the cap on the native-TLS (Imperva bypass) and Opera Mini
transports over loopback HTTP, including compression-bomb cases where a
tiny compressed body would expand far past the cap.
"""

import gzip
import threading
import zlib
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from wafer import ResponseTooLarge
from wafer._errors import TooManyRedirects
from wafer._native_tls import NativeTLSTransport, _decompress
from wafer._opera_mini import OperaMiniIdentity


def _serve(handler_cls):
    """Start a loopback HTTPServer; return (port, shutdown_fn)."""
    srv = HTTPServer(("127.0.0.1", 0), handler_cls)
    port = srv.server_address[1]
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()

    def shutdown():
        srv.shutdown()
        thread.join(timeout=5)

    return port, shutdown


def _handler(body: bytes, *, content_encoding=None, send_length=True):
    """Build a BaseHTTPRequestHandler that serves a fixed body."""

    class Handler(BaseHTTPRequestHandler):
        def _respond(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            if content_encoding:
                self.send_header("Content-Encoding", content_encoding)
            if send_length:
                self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_GET = _respond
        do_POST = _respond

        def log_message(self, *args):
            pass

    return Handler


# ---------------------------------------------------------------------------
# Decompressor-level bounds (the gzip/deflate bomb guard)
# ---------------------------------------------------------------------------


class TestDecompressBound:
    def test_gzip_under_cap_returns_full(self):
        raw = b"hello world"
        comp = gzip.compress(raw)
        assert _decompress(comp, "gzip", "u", max_size=100) == raw

    def test_gzip_bomb_raises_without_full_expansion(self):
        # 1 MiB of zeros compresses to a few hundred bytes; with a 1 KiB cap
        # the decompressor must stop and raise, never buffering the 1 MiB.
        raw = b"\x00" * (1024 * 1024)
        comp = gzip.compress(raw)
        assert len(comp) < 2000  # the "bomb": tiny compressed
        with pytest.raises(ResponseTooLarge) as ei:
            _decompress(comp, "gzip", "u", max_size=1024)
        assert ei.value.limit == 1024
        assert ei.value.size > 1024

    def test_gzip_no_cap_full_expansion(self):
        raw = b"\x00" * (256 * 1024)
        comp = gzip.compress(raw)
        assert _decompress(comp, "gzip", "u", max_size=None) == raw

    def test_deflate_under_cap_returns_full(self):
        raw = b"deflate body here"
        comp = zlib.compress(raw)
        assert _decompress(comp, "deflate", "u", max_size=100) == raw

    def test_deflate_bomb_raises(self):
        raw = b"\x00" * (1024 * 1024)
        comp = zlib.compress(raw)
        assert len(comp) < 2000
        with pytest.raises(ResponseTooLarge):
            _decompress(comp, "deflate", "u", max_size=1024)

    def test_exact_fit_does_not_raise(self):
        # Decompressed length == cap is allowed (only > cap raises).
        for enc, comp in (
            ("gzip", gzip.compress(b"a" * 100)),
            ("deflate", zlib.compress(b"a" * 100)),
        ):
            assert _decompress(comp, enc, "u", max_size=100) == b"a" * 100

    def test_over_by_one_raises(self):
        # cap+1 bytes must raise (the off-by-one boundary, gzip and deflate).
        for enc, comp in (
            ("gzip", gzip.compress(b"a" * 101)),
            ("deflate", zlib.compress(b"a" * 101)),
        ):
            with pytest.raises(ResponseTooLarge):
                _decompress(comp, enc, "u", max_size=100)

    def test_raw_deflate_bomb_raises(self):
        # Headerless (raw) deflate, as some servers send.
        raw = b"\x00" * (1024 * 1024)
        co = zlib.compressobj(wbits=-zlib.MAX_WBITS)
        comp = co.compress(raw) + co.flush()
        with pytest.raises(ResponseTooLarge):
            _decompress(comp, "deflate", "u", max_size=1024)


# ---------------------------------------------------------------------------
# Native-TLS transport (over loopback HTTP)
# ---------------------------------------------------------------------------


class TestNativeTransportCap:
    def test_under_cap_passes(self):
        port, stop = _serve(_handler(b"<html>" + b"x" * 100 + b"</html>"))
        try:
            t = NativeTLSTransport()
            status, _, body, _, _ = t.request(
                "GET", f"http://127.0.0.1:{port}/x", {}, max_size=10_000
            )
            assert status == 200
            assert len(body) == 113  # "<html>" + 100 + "</html>"
        finally:
            stop()

    def test_content_length_short_circuit(self):
        # Declared Content-Length over the cap raises before the body read.
        port, stop = _serve(_handler(b"y" * 5000))
        try:
            t = NativeTLSTransport()
            with pytest.raises(ResponseTooLarge) as ei:
                t.request(
                    "GET", f"http://127.0.0.1:{port}/x", {}, max_size=500
                )
            assert ei.value.size == 5000
            assert ei.value.limit == 500
        finally:
            stop()

    def test_chunked_read_over_cap_raises(self):
        # No Content-Length: the cap is enforced on the streamed wire read.
        port, stop = _serve(_handler(b"y" * 5000, send_length=False))
        try:
            t = NativeTLSTransport()
            with pytest.raises(ResponseTooLarge) as ei:
                t.request(
                    "GET", f"http://127.0.0.1:{port}/x", {}, max_size=500
                )
            assert ei.value.limit == 500
            assert ei.value.size > 500
        finally:
            stop()

    def test_gzip_bomb_over_cap_raises(self):
        raw = b"\x00" * (1024 * 1024)
        comp = gzip.compress(raw)
        # No Content-Length so the compressed-length short-circuit can't fire;
        # the cap must be enforced on the DECOMPRESSED output.
        port, stop = _serve(
            _handler(comp, content_encoding="gzip", send_length=False)
        )
        try:
            t = NativeTLSTransport()
            with pytest.raises(ResponseTooLarge):
                t.request(
                    "GET", f"http://127.0.0.1:{port}/x", {}, max_size=4096
                )
        finally:
            stop()

    def test_default_none_unchanged(self):
        raw = b"q" * 50_000
        port, stop = _serve(_handler(raw))
        try:
            t = NativeTLSTransport()
            status, _, body, _, _ = t.request(
                "GET", f"http://127.0.0.1:{port}/x", {}
            )
            assert status == 200
            assert len(body) == 50_000
        finally:
            stop()


# ---------------------------------------------------------------------------
# Opera Mini transport (over loopback HTTP)
# ---------------------------------------------------------------------------


class TestOperaMiniCap:
    def test_under_cap_passes(self):
        port, stop = _serve(_handler(b"<html>ok</html>"))
        try:
            ident = OperaMiniIdentity()
            status, _, body, _, _ = ident.request(
                f"http://127.0.0.1:{port}/x", max_size=10_000
            )
            assert status == 200
            assert b"ok" in body
        finally:
            stop()

    def test_content_length_short_circuit(self):
        port, stop = _serve(_handler(b"y" * 5000))
        try:
            ident = OperaMiniIdentity()
            with pytest.raises(ResponseTooLarge) as ei:
                ident.request(
                    f"http://127.0.0.1:{port}/x", max_size=500
                )
            assert ei.value.size == 5000
        finally:
            stop()

    def test_chunked_read_over_cap_raises(self):
        port, stop = _serve(_handler(b"y" * 5000, send_length=False))
        try:
            ident = OperaMiniIdentity()
            with pytest.raises(ResponseTooLarge) as ei:
                ident.request(
                    f"http://127.0.0.1:{port}/x", max_size=500
                )
            assert ei.value.limit == 500
        finally:
            stop()

    def test_gzip_bomb_over_cap_raises(self):
        raw = b"\x00" * (1024 * 1024)
        comp = gzip.compress(raw)
        port, stop = _serve(
            _handler(comp, content_encoding="gzip", send_length=False)
        )
        try:
            ident = OperaMiniIdentity()
            with pytest.raises(ResponseTooLarge):
                ident.request(
                    f"http://127.0.0.1:{port}/x", max_size=4096
                )
        finally:
            stop()

    def test_default_none_unchanged(self):
        raw = b"q" * 50_000
        port, stop = _serve(_handler(raw))
        try:
            ident = OperaMiniIdentity()
            status, _, body, _, _ = ident.request(
                f"http://127.0.0.1:{port}/x"
            )
            assert status == 200
            assert len(body) == 50_000
        finally:
            stop()


def _redirect_handler():
    """A handler that always 302s back to itself (an infinite loop)."""

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", self.path)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args):
            pass

    return Handler


class TestNativeRedirectBudget:
    """FIX 7 (optional): the native-TLS redirect chain raises
    TooManyRedirects when the hop budget is exhausted, aligned with the
    session max_redirects (rather than returning a dangling 3xx)."""

    def test_redirect_loop_raises_too_many(self):
        port, stop = _serve(_redirect_handler())
        try:
            t = NativeTLSTransport(max_redirects=3)
            with pytest.raises(TooManyRedirects) as ei:
                t.request("GET", f"http://127.0.0.1:{port}/loop", {})
            assert ei.value.max_redirects == 3
        finally:
            stop()

    def test_no_follow_single_redirect_returned(self):
        # follow_redirects=False: the single 3xx is returned, not raised.
        port, stop = _serve(_redirect_handler())
        try:
            t = NativeTLSTransport(follow_redirects=False)
            status, _, _, _, _ = t.request(
                "GET", f"http://127.0.0.1:{port}/loop", {}
            )
            assert status == 302
        finally:
            stop()
