"""Tests for WaferResponse wrapper."""

import datetime
import json

import pytest

from wafer._base import _is_binary_content_type, _normalize_timeout
from wafer._errors import (
    ChallengeDetected,
    EmptyResponse,
    RateLimited,
    WaferError,
    WaferHTTPError,
    WaferTimeout,
)
from wafer._response import HistoryEntry, WaferResponse


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


class TestGetAll:
    """Tests for WaferResponse.get_all() multi-value header access."""

    def test_get_all_returns_list_from_joined_headers(self):
        """Without raw response, splits the joined '; ' string back."""
        resp = WaferResponse(
            status_code=200,
            text="ok",
            headers={"set-cookie": "a=1; b=2"},
            url="https://example.com",
        )
        # No _raw, so falls back to headers dict
        result = resp.get_all("set-cookie")
        assert result == ["a=1; b=2"]

    def test_get_all_missing_key_returns_empty_list(self):
        resp = WaferResponse(
            status_code=200,
            text="ok",
            headers={},
            url="https://example.com",
        )
        assert resp.get_all("set-cookie") == []

    def test_get_all_single_value_returns_single_element_list(self):
        resp = WaferResponse(
            status_code=200,
            text="ok",
            headers={"content-type": "text/html"},
            url="https://example.com",
        )
        result = resp.get_all("content-type")
        assert result == ["text/html"]

    def test_get_all_with_raw_response(self):
        """With a mock raw response, delegates to raw.headers.get_all()."""

        class MockHeaders:
            def get_all(self, key):
                if key == "set-cookie":
                    return [b"a=1; Path=/", b"b=2; Path=/"]
                return []

        class MockRaw:
            headers = MockHeaders()

        resp = WaferResponse(
            status_code=200,
            text="ok",
            headers={"set-cookie": "a=1; Path=/; b=2; Path=/"},
            url="https://example.com",
            raw=MockRaw(),
        )
        result = resp.get_all("set-cookie")
        assert result == ["a=1; Path=/", "b=2; Path=/"]

    def test_get_all_with_raw_response_string_values(self):
        """Raw response returning string values (not bytes)."""

        class MockHeaders:
            def get_all(self, key):
                if key == "x-custom":
                    return ["value1", "value2", "value3"]
                return []

        class MockRaw:
            headers = MockHeaders()

        resp = WaferResponse(
            status_code=200,
            text="ok",
            headers={},
            url="https://example.com",
            raw=MockRaw(),
        )
        result = resp.get_all("x-custom")
        assert result == ["value1", "value2", "value3"]

    def test_get_all_empty_header_value_returns_empty_list(self):
        """An empty string header value returns empty list."""
        resp = WaferResponse(
            status_code=200,
            text="ok",
            headers={"x-empty": ""},
            url="https://example.com",
        )
        assert resp.get_all("x-empty") == []


class TestRawSetCookie:
    """Tests for the raw_set_cookie field (native-TLS / Opera Mini paths).

    Those transports decode headers into a flat dict where multiple
    Set-Cookie values are joined with '; ' (ambiguous - cookie attributes
    use the same separator), so the individual values ride along in
    raw_set_cookie.
    """

    RAW = [
        "reese84=tok123; Path=/; Secure; HttpOnly",
        "incap_ses_1226_9=abc; Path=/",
        "visid_incap_9=xyz; Domain=.realtor.ca; Path=/",
    ]

    def _resp(self, raw_set_cookie):
        return WaferResponse(
            status_code=200,
            text="ok",
            # joined form, as the native-TLS/Opera Mini header dicts hold it
            headers={"set-cookie": "; ".join(self.RAW)},
            url="https://api2.realtor.ca/x",
            raw_set_cookie=raw_set_cookie,
        )

    def test_get_all_returns_individual_values(self):
        resp = self._resp(self.RAW)
        assert resp.get_all("set-cookie") == self.RAW
        assert resp.get_all("Set-Cookie") == self.RAW  # case-insensitive

    def test_cookies_sees_every_cookie(self):
        resp = self._resp(self.RAW)
        assert resp.cookies == {
            "reese84": "tok123",
            "incap_ses_1226_9": "abc",
            "visid_incap_9": "xyz",
        }

    def test_none_falls_back_to_joined_header(self):
        """Without raw_set_cookie the old (lossy) fallback still applies."""
        resp = self._resp(None)
        assert resp.get_all("set-cookie") == ["; ".join(self.RAW)]
        # Only the first cookie survives the join - documented limitation
        # of the fallback, which raw_set_cookie exists to avoid.
        assert resp.cookies == {"reese84": "tok123"}

    def test_other_headers_unaffected(self):
        resp = self._resp(self.RAW)
        assert resp.get_all("content-type") == []

    def test_raw_set_cookie_defensively_copied(self):
        raw = list(self.RAW)
        resp = self._resp(raw)
        raw.append("evil=1")
        assert resp.get_all("set-cookie") == self.RAW
        # and the returned list is a copy too
        resp.get_all("set-cookie").append("evil=2")
        assert resp.get_all("set-cookie") == self.RAW

    def test_raw_set_cookie_wins_over_raw_response(self):
        """When both raw_set_cookie and a raw response are present,
        the explicit list wins (it is the transport's ground truth)."""

        class MockHeaders:
            def get_all(self, key):
                return [b"other=1"]

        class MockRaw:
            headers = MockHeaders()

        resp = WaferResponse(
            status_code=200,
            text="ok",
            headers={},
            url="https://example.com",
            raw=MockRaw(),
            raw_set_cookie=["a=1; Path=/"],
        )
        assert resp.get_all("set-cookie") == ["a=1; Path=/"]
        # non-Set-Cookie keys still go through the raw response
        assert resp.get_all("x-other") == ["other=1"]


class TestTextCharset:
    """Tests for charset-aware resp.text decoding."""

    def test_charset_from_content_type_header(self):
        content = "café".encode("latin-1")
        resp = WaferResponse(
            status_code=200,
            content=content,
            headers={"content-type": "text/html; charset=ISO-8859-1"},
            url="https://example.com",
        )
        assert resp.text == "café"

    def test_charset_header_quoted_value(self):
        content = "héllo".encode("latin-1")
        resp = WaferResponse(
            status_code=200,
            content=content,
            headers={"content-type": 'text/plain; charset="iso-8859-1"'},
            url="https://example.com",
        )
        assert resp.text == "héllo"

    def test_meta_charset_tag_sniffed(self):
        html = (
            '<html><head><meta charset="windows-1252"></head>'
            "<body>café</body></html>"
        )
        resp = WaferResponse(
            status_code=200,
            content=html.encode("windows-1252"),
            headers={"content-type": "text/html"},
            url="https://example.com",
        )
        assert "café" in resp.text

    def test_meta_http_equiv_sniffed(self):
        html = (
            '<html><head><meta http-equiv="Content-Type" '
            'content="text/html; charset=shift_jis"></head>'
            "<body>日本語</body></html>"
        )
        resp = WaferResponse(
            status_code=200,
            content=html.encode("shift_jis"),
            headers={"content-type": "text/html"},
            url="https://example.com",
        )
        assert "日本語" in resp.text

    def test_header_charset_wins_over_meta(self):
        html = '<meta charset="utf-8"><body>café</body>'
        resp = WaferResponse(
            status_code=200,
            content=html.encode("latin-1"),
            headers={"content-type": "text/html; charset=latin-1"},
            url="https://example.com",
        )
        assert "café" in resp.text

    def test_invalid_charset_falls_back_to_utf8(self):
        content = "café".encode("utf-8")
        resp = WaferResponse(
            status_code=200,
            content=content,
            headers={"content-type": "text/html; charset=bogus-charset-x"},
            url="https://example.com",
        )
        assert resp.text == "café"

    def test_invalid_meta_charset_falls_back_to_utf8(self):
        html = '<meta charset="not-a-real-charset">café'
        resp = WaferResponse(
            status_code=200,
            content=html.encode("utf-8"),
            headers={"content-type": "text/html"},
            url="https://example.com",
        )
        assert "café" in resp.text

    def test_no_charset_defaults_to_utf8(self):
        resp = WaferResponse(
            status_code=200,
            content="café".encode("utf-8"),
            headers={"content-type": "text/html"},
            url="https://example.com",
        )
        assert resp.text == "café"

    def test_meta_not_sniffed_for_non_html(self):
        # JSON containing a meta-like string must not trigger sniffing:
        # the utf-8 bytes would be mangled if decoded as latin-1.
        body = '{"snippet": "<meta charset=latin-1>", "v": "café"}'
        resp = WaferResponse(
            status_code=200,
            content=body.encode("utf-8"),
            headers={"content-type": "application/json"},
            url="https://example.com",
        )
        assert "café" in resp.text

    def test_meta_not_sniffed_for_missing_mime_non_markup_body(self):
        # No Content-Type at all + a body that does NOT look like markup:
        # the meta-like string inside the JSON must not cause a latin-1
        # decode of utf-8 bytes (codec confusion).
        body = '{"snippet": "<meta charset=latin-1>", "v": "café"}'
        resp = WaferResponse(
            status_code=200,
            content=body.encode("utf-8"),
            headers={},
            url="https://example.com",
        )
        assert "café" in resp.text

    def test_meta_sniffed_for_missing_mime_markup_body(self):
        # No Content-Type, but the body looks like markup (first
        # non-whitespace byte is '<') -> meta sniff still applies.
        html = '\n  <html><meta charset="windows-1252"><body>café</body>'
        resp = WaferResponse(
            status_code=200,
            content=html.encode("windows-1252"),
            headers={},
            url="https://example.com",
        )
        assert "café" in resp.text

    def test_meta_beyond_first_kb_ignored(self):
        padding = "<!-- " + "x" * 1100 + " -->"
        html = padding + '<meta charset="latin-1">café'
        resp = WaferResponse(
            status_code=200,
            content=html.encode("latin-1"),
            headers={"content-type": "text/html"},
            url="https://example.com",
        )
        # Meta tag is outside the 1KB sniff window -> utf-8 fallback,
        # and the latin-1 e-acute byte becomes a replacement character.
        assert "�" in resp.text

    def test_decode_never_raises(self):
        # Bytes invalid for the declared charset decode with replacement.
        resp = WaferResponse(
            status_code=200,
            content=b"\xff\xfe invalid \x9d",
            headers={"content-type": "text/html; charset=utf-8"},
            url="https://example.com",
        )
        assert isinstance(resp.text, str)

    def test_text_cached_after_first_access(self):
        resp = WaferResponse(
            status_code=200,
            content=b"hello",
            headers={"content-type": "text/html; charset=utf-8"},
            url="https://example.com",
        )
        assert resp.text is resp.text

    def test_predecoded_text_bypasses_charset(self):
        # When text= was provided (wreq already decoded), it is returned
        # as-is regardless of headers.
        resp = WaferResponse(
            status_code=200,
            text="already decoded",
            headers={"content-type": "text/html; charset=shift_jis"},
            url="https://example.com",
        )
        assert resp.text == "already decoded"


class TestResponseCookies:
    """Tests for resp.cookies (Set-Cookie parsing)."""

    def test_cookies_from_single_set_cookie(self):
        resp = WaferResponse(
            status_code=200,
            text="ok",
            headers={"set-cookie": "session=abc123; Path=/; HttpOnly"},
            url="https://example.com",
        )
        assert resp.cookies == {"session": "abc123"}

    def test_cookies_multiple_via_raw(self):
        class MockHeaders:
            def get_all(self, key):
                if key == "set-cookie":
                    return [
                        b"a=1; Path=/",
                        b"b=2; Secure; HttpOnly",
                        b"c=x=y; Path=/",
                    ]
                return []

        class MockRaw:
            headers = MockHeaders()

        resp = WaferResponse(
            status_code=200,
            text="ok",
            headers={"set-cookie": "a=1; Path=/"},
            url="https://example.com",
            raw=MockRaw(),
        )
        # Value containing '=' is preserved past the first separator
        assert resp.cookies == {"a": "1", "b": "2", "c": "x=y"}

    def test_cookies_empty_without_set_cookie(self):
        resp = WaferResponse(
            status_code=200,
            text="ok",
            headers={},
            url="https://example.com",
        )
        assert resp.cookies == {}

    def test_cookies_malformed_entries_skipped(self):
        class MockHeaders:
            def get_all(self, key):
                if key == "set-cookie":
                    return ["no_equals_sign", "=nameless", "ok=fine"]
                return []

        class MockRaw:
            headers = MockHeaders()

        resp = WaferResponse(
            status_code=200,
            text="ok",
            headers={},
            url="https://example.com",
            raw=MockRaw(),
        )
        assert resp.cookies == {"ok": "fine"}

    def test_cookies_cached(self):
        resp = WaferResponse(
            status_code=200,
            text="ok",
            headers={"set-cookie": "a=1; Path=/"},
            url="https://example.com",
        )
        assert resp.cookies is resp.cookies


class TestHistoryAttribute:
    """Tests for resp.history default and HistoryEntry shape."""

    def test_history_default_empty_list(self):
        resp = WaferResponse(
            status_code=200, text="", headers={}, url="https://example.com"
        )
        assert resp.history == []

    def test_history_passed_through(self):
        hops = [HistoryEntry(301, "https://example.com/old")]
        resp = WaferResponse(
            status_code=200,
            text="",
            headers={},
            url="https://example.com/new",
            history=hops,
        )
        assert resp.history == hops

    def test_history_entry_fields_and_tuple_equality(self):
        entry = HistoryEntry(302, "https://example.com/a")
        assert entry.status_code == 302
        assert entry.url == "https://example.com/a"
        assert entry == (302, "https://example.com/a")

    def test_history_defensively_copied(self):
        """Mutating the list passed as history= must not alias the
        response's history."""
        hops = [HistoryEntry(301, "https://example.com/old")]
        resp = WaferResponse(
            status_code=200,
            text="",
            headers={},
            url="https://example.com/new",
            history=hops,
        )
        hops.append(HistoryEntry(302, "https://example.com/other"))
        assert resp.history == [HistoryEntry(301, "https://example.com/old")]


class TestExceptionResponse:
    """Tests for the response= kwarg on raised wafer exceptions."""

    def test_challenge_detected_response_default_none(self):
        exc = ChallengeDetected("cloudflare", "https://example.com", 403)
        assert exc.response is None

    def test_challenge_detected_carries_response(self):
        resp = WaferResponse(
            status_code=403, text="blocked", headers={}, url="https://example.com"
        )
        exc = ChallengeDetected(
            "cloudflare", "https://example.com", 403, response=resp
        )
        assert exc.response is resp
        assert exc.challenge_type == "cloudflare"
        assert exc.status_code == 403

    def test_rate_limited_carries_response(self):
        resp = WaferResponse(
            status_code=429, text="slow down", headers={}, url="https://example.com"
        )
        exc = RateLimited("https://example.com", 5.0, response=resp)
        assert exc.response is resp
        assert exc.retry_after == 5.0

    def test_rate_limited_response_default_none(self):
        exc = RateLimited("https://example.com")
        assert exc.response is None

    def test_empty_response_carries_response(self):
        resp = WaferResponse(
            status_code=200, text="", headers={}, url="https://example.com"
        )
        exc = EmptyResponse("https://example.com", 200, response=resp)
        assert exc.response is resp

    def test_empty_response_default_none(self):
        exc = EmptyResponse("https://example.com", 200)
        assert exc.response is None

    def test_positional_args_backward_compatible(self):
        # Existing positional call shapes must keep working unchanged.
        exc1 = ChallengeDetected("datadome", "https://x.com", 403)
        assert exc1.url == "https://x.com"
        exc2 = RateLimited("https://x.com", 3.0)
        assert exc2.retry_after == 3.0
        exc3 = EmptyResponse("https://x.com", 200)
        assert exc3.status_code == 200


class TestWaferTimeout:
    """Tests for WaferTimeout exception hierarchy."""

    def test_is_wafer_error(self):
        assert issubclass(WaferTimeout, WaferError)

    def test_is_timeout_error(self):
        assert issubclass(WaferTimeout, TimeoutError)

    def test_caught_by_wafer_error(self):
        with pytest.raises(WaferError):
            raise WaferTimeout("https://example.com", 10.0)

    def test_caught_by_timeout_error(self):
        with pytest.raises(TimeoutError):
            raise WaferTimeout("https://example.com", 10.0)

    def test_attributes(self):
        exc = WaferTimeout("https://example.com/path", 5.5)
        assert exc.url == "https://example.com/path"
        assert exc.timeout_secs == 5.5
        assert "5.5s" in str(exc)


class TestNormalizeTimeout:
    """Tests for float/int timeout normalization."""

    def test_float_seconds(self):
        result = _normalize_timeout(10.0)
        assert isinstance(result, datetime.timedelta)
        assert result.total_seconds() == 10.0

    def test_int_seconds(self):
        result = _normalize_timeout(30)
        assert isinstance(result, datetime.timedelta)
        assert result.total_seconds() == 30.0

    def test_timedelta_passthrough(self):
        td = datetime.timedelta(seconds=15)
        result = _normalize_timeout(td)
        assert result is td


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
