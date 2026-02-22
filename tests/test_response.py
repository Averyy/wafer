"""Tests for WaferResponse wrapper."""

import json

import pytest

from wafer._base import _is_binary_content_type
from wafer._errors import WaferHTTPError
from wafer._response import WaferResponse


class TestWaferResponse:
    def test_status_code(self):
        resp = WaferResponse(
            status_code=200, text="ok", headers={}, url="https://example.com"
        )
        assert resp.status_code == 200

    def test_ok_true_for_200(self):
        resp = WaferResponse(
            status_code=200, text="", headers={}, url="https://example.com"
        )
        assert resp.ok is True

    def test_ok_true_for_299(self):
        resp = WaferResponse(
            status_code=299, text="", headers={}, url="https://example.com"
        )
        assert resp.ok is True

    def test_ok_false_for_404(self):
        resp = WaferResponse(
            status_code=404, text="", headers={}, url="https://example.com"
        )
        assert resp.ok is False

    def test_ok_false_for_500(self):
        resp = WaferResponse(
            status_code=500, text="", headers={}, url="https://example.com"
        )
        assert resp.ok is False

    def test_ok_false_for_301(self):
        resp = WaferResponse(
            status_code=301, text="", headers={}, url="https://example.com"
        )
        assert resp.ok is False

    def test_text_is_str(self):
        resp = WaferResponse(
            status_code=200,
            text="hello world",
            headers={},
            url="https://example.com",
        )
        assert resp.text == "hello world"
        assert isinstance(resp.text, str)

    def test_content_is_bytes(self):
        resp = WaferResponse(
            status_code=200,
            text="hello",
            headers={},
            url="https://example.com",
        )
        assert resp.content == b"hello"
        assert isinstance(resp.content, bytes)

    def test_content_utf8(self):
        resp = WaferResponse(
            status_code=200,
            text="caf\u00e9",
            headers={},
            url="https://example.com",
        )
        assert resp.content == "caf\u00e9".encode("utf-8")

    def test_json_parses_body(self):
        body = json.dumps({"key": "value", "num": 42})
        resp = WaferResponse(
            status_code=200,
            text=body,
            headers={},
            url="https://example.com",
        )
        data = resp.json()
        assert data == {"key": "value", "num": 42}

    def test_json_raises_on_invalid(self):
        resp = WaferResponse(
            status_code=200,
            text="not json",
            headers={},
            url="https://example.com",
        )
        with pytest.raises(json.JSONDecodeError):
            resp.json()

    def test_headers_dict(self):
        resp = WaferResponse(
            status_code=200,
            text="",
            headers={"content-type": "text/html", "x-custom": "val"},
            url="https://example.com",
        )
        assert resp.headers["content-type"] == "text/html"
        assert resp.headers["x-custom"] == "val"

    def test_url(self):
        resp = WaferResponse(
            status_code=200,
            text="",
            headers={},
            url="https://example.com/path?q=1",
        )
        assert resp.url == "https://example.com/path?q=1"

    def test_raise_for_status_ok(self):
        resp = WaferResponse(
            status_code=200, text="", headers={}, url="https://example.com"
        )
        resp.raise_for_status()  # should not raise

    def test_raise_for_status_404(self):
        resp = WaferResponse(
            status_code=404,
            text="",
            headers={},
            url="https://example.com/missing",
        )
        with pytest.raises(WaferHTTPError) as exc_info:
            resp.raise_for_status()
        assert exc_info.value.status_code == 404
        assert exc_info.value.url == "https://example.com/missing"

    def test_raise_for_status_500(self):
        resp = WaferResponse(
            status_code=500, text="", headers={}, url="https://example.com"
        )
        with pytest.raises(WaferHTTPError):
            resp.raise_for_status()

    def test_elapsed(self):
        resp = WaferResponse(
            status_code=200,
            text="",
            headers={},
            url="https://example.com",
            elapsed=1.5,
        )
        assert resp.elapsed == 1.5

    def test_was_retried_default_false(self):
        resp = WaferResponse(
            status_code=200, text="", headers={}, url="https://example.com"
        )
        assert resp.was_retried is False

    def test_was_retried_true(self):
        resp = WaferResponse(
            status_code=200,
            text="",
            headers={},
            url="https://example.com",
            was_retried=True,
        )
        assert resp.was_retried is True

    def test_challenge_type_default_none(self):
        resp = WaferResponse(
            status_code=200, text="", headers={}, url="https://example.com"
        )
        assert resp.challenge_type is None

    def test_challenge_type_set(self):
        resp = WaferResponse(
            status_code=200,
            text="",
            headers={},
            url="https://example.com",
            challenge_type="cloudflare",
        )
        assert resp.challenge_type == "cloudflare"

    def test_repr(self):
        resp = WaferResponse(
            status_code=404, text="", headers={}, url="https://example.com"
        )
        assert repr(resp) == "<WaferResponse [404]>"

    def test_raw_accessible(self):
        sentinel = object()
        resp = WaferResponse(
            status_code=200,
            text="",
            headers={},
            url="https://example.com",
            raw=sentinel,
        )
        assert resp._raw is sentinel


class TestIsBinaryContentType:
    """Tests for _is_binary_content_type helper."""

    def test_image_types(self):
        assert _is_binary_content_type("image/png") is True
        assert _is_binary_content_type("image/jpeg") is True
        assert _is_binary_content_type("image/webp") is True

    def test_pdf(self):
        assert _is_binary_content_type("application/pdf") is True

    def test_octet_stream(self):
        assert _is_binary_content_type("application/octet-stream") is True

    def test_zip(self):
        assert _is_binary_content_type("application/zip") is True
        assert _is_binary_content_type("application/gzip") is True

    def test_wasm(self):
        assert _is_binary_content_type("application/wasm") is True

    def test_audio_video(self):
        assert _is_binary_content_type("audio/mpeg") is True
        assert _is_binary_content_type("video/mp4") is True

    def test_text_html_is_not_binary(self):
        assert _is_binary_content_type("text/html") is False
        assert _is_binary_content_type("text/html; charset=utf-8") is False

    def test_json_is_not_binary(self):
        assert _is_binary_content_type("application/json") is False

    def test_empty_is_not_binary(self):
        assert _is_binary_content_type("") is False

    def test_text_plain_is_not_binary(self):
        assert _is_binary_content_type("text/plain") is False

    def test_javascript_is_not_binary(self):
        assert _is_binary_content_type("application/javascript") is False

    def test_case_insensitive(self):
        assert _is_binary_content_type("Image/PNG") is True
        assert _is_binary_content_type("APPLICATION/PDF") is True

    def test_with_charset_param(self):
        assert _is_binary_content_type("image/png; charset=utf-8") is True


class TestBinaryContent:
    """Tests for binary content handling (PDFs, images, etc.)."""

    def test_content_from_bytes(self):
        """Binary response: content is raw bytes, text is lazy decoded."""
        raw = b"\x89PNG\r\n\x1a\n\x00\x00\x00"
        resp = WaferResponse(
            status_code=200,
            content=raw,
            headers={"content-type": "image/png"},
            url="https://example.com/image.png",
        )
        assert resp.content == raw
        assert isinstance(resp.content, bytes)

    def test_text_decoded_from_binary(self):
        """Binary content decoded to text with replacement chars."""
        raw = b"\x89PNG\r\n"
        resp = WaferResponse(
            status_code=200,
            content=raw,
            headers={},
            url="https://example.com/image.png",
        )
        # text property should decode with errors="replace"
        assert isinstance(resp.text, str)
        assert "\ufffd" in resp.text  # replacement character

    def test_text_from_text_kwarg(self):
        """When text= is provided, content is derived from it."""
        resp = WaferResponse(
            status_code=200,
            text="hello",
            headers={},
            url="https://example.com",
        )
        assert resp.text == "hello"
        assert resp.content == b"hello"

    def test_content_preserved_for_pdf(self):
        """PDF bytes are preserved exactly in content."""
        pdf_bytes = b"%PDF-1.4 fake pdf content \x00\xff"
        resp = WaferResponse(
            status_code=200,
            content=pdf_bytes,
            headers={"content-type": "application/pdf"},
            url="https://example.com/doc.pdf",
        )
        assert resp.content == pdf_bytes
        assert len(resp.content) == len(pdf_bytes)

    def test_both_content_and_text(self):
        """When both content and text are provided, both are stored."""
        resp = WaferResponse(
            status_code=200,
            content=b"raw bytes",
            text="decoded text",
            headers={},
            url="https://example.com",
        )
        assert resp.content == b"raw bytes"
        assert resp.text == "decoded text"

    def test_empty_content_default(self):
        """Default content is empty bytes."""
        resp = WaferResponse(
            status_code=200,
            headers={},
            url="https://example.com",
        )
        assert resp.content == b""
        assert resp.text == ""
