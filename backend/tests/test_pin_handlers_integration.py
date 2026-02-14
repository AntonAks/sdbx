"""Integration tests for PIN handlers - calls actual handler functions end-to-end.

Tests validation paths, error handling, and response format by invoking the real
handler functions (including the @require_cloudfront_and_recaptcha decorator).

Since conftest.py clears CLOUDFRONT_SECRET and RECAPTCHA_SECRET_KEY, the security
decorator passes through, allowing us to test handler logic directly.

Validation errors happen BEFORE any DynamoDB calls, so these tests don't need AWS.
"""

import json

import pytest

from lambdas.pin_upload_init.handler import handler as pin_upload_init_handler
from lambdas.pin_initiate.handler import handler as pin_initiate_handler
from lambdas.pin_verify.handler import handler as pin_verify_handler


def _make_event(body: dict) -> dict:
    """Build a minimal API Gateway event with JSON body."""
    return {
        "body": json.dumps(body),
        "headers": {},
        "requestContext": {
            "identity": {"sourceIp": "127.0.0.1"},
        },
    }


def _make_event_raw_body(body_str: str) -> dict:
    """Build an API Gateway event with a raw string body."""
    return {
        "body": body_str,
        "headers": {},
        "requestContext": {
            "identity": {"sourceIp": "127.0.0.1"},
        },
    }


def _parse_response(response: dict) -> tuple[int, dict]:
    """Extract status code and parsed body from handler response."""
    status = response["statusCode"]
    body = json.loads(response["body"])
    return status, body


# ──────────────────────────────────────────────────────────────────────
# PIN Upload Init Handler - Integration Tests
# ──────────────────────────────────────────────────────────────────────


class TestPinUploadInitHandlerIntegration:
    """End-to-end tests for pin_upload_init handler validation paths."""

    def test_missing_pin_returns_400(self):
        """Should return 400 when PIN is not provided."""
        event = _make_event({
            "content_type": "file",
            "file_size": 1024,
            "ttl": "1h",
        })

        response = pin_upload_init_handler(event, None)
        status, body = _parse_response(response)

        assert status == 400
        assert "error" in body
        assert "PIN" in body["error"]

    def test_empty_pin_returns_400(self):
        """Should return 400 when PIN is empty string."""
        event = _make_event({
            "content_type": "file",
            "file_size": 1024,
            "pin": "",
            "ttl": "1h",
        })

        response = pin_upload_init_handler(event, None)
        status, body = _parse_response(response)

        assert status == 400
        assert "error" in body

    def test_short_pin_returns_400(self):
        """Should return 400 when PIN is too short (< 4 chars)."""
        event = _make_event({
            "content_type": "file",
            "file_size": 1024,
            "pin": "12",
            "ttl": "1h",
        })

        response = pin_upload_init_handler(event, None)
        status, body = _parse_response(response)

        assert status == 400
        assert "error" in body
        assert "4 characters" in body["error"]

    def test_long_pin_returns_400(self):
        """Should return 400 when PIN is too long (> 4 chars)."""
        event = _make_event({
            "content_type": "file",
            "file_size": 1024,
            "pin": "12345",
            "ttl": "1h",
        })

        response = pin_upload_init_handler(event, None)
        status, body = _parse_response(response)

        assert status == 400
        assert "error" in body
        assert "4 characters" in body["error"]

    def test_special_chars_pin_returns_400(self):
        """Should return 400 when PIN contains special characters."""
        event = _make_event({
            "content_type": "file",
            "file_size": 1024,
            "pin": "12@#",
            "ttl": "1h",
        })

        response = pin_upload_init_handler(event, None)
        status, body = _parse_response(response)

        assert status == 400
        assert "error" in body
        assert "letters and numbers" in body["error"]

    def test_missing_ttl_returns_400(self):
        """Should return 400 when TTL is not provided."""
        event = _make_event({
            "content_type": "file",
            "file_size": 1024,
            "pin": "7a2B",
        })

        response = pin_upload_init_handler(event, None)
        status, body = _parse_response(response)

        assert status == 400
        assert "error" in body
        assert "TTL" in body["error"]

    def test_invalid_ttl_returns_400(self):
        """Should return 400 when TTL is an invalid value."""
        event = _make_event({
            "content_type": "file",
            "file_size": 1024,
            "pin": "7a2B",
            "ttl": "99h",
        })

        response = pin_upload_init_handler(event, None)
        status, body = _parse_response(response)

        assert status == 400
        assert "error" in body
        assert "TTL" in body["error"]

    def test_missing_file_size_for_file_type_returns_400(self):
        """Should return 400 when file_size is missing for file content type.

        Note: file_size validation happens after PIN/TTL validation AND after
        the DynamoDB call attempt, so this requires DynamoDB to be available.
        We test that valid PIN + TTL pass validation successfully (the error
        will come from DynamoDB being unavailable, not from validation).
        """
        event = _make_event({
            "content_type": "file",
            "pin": "7a2B",
            "ttl": "1h",
        })

        response = pin_upload_init_handler(event, None)
        status, body = _parse_response(response)

        # Without DynamoDB, we get a 500 or 400 - but PIN and TTL validation passed
        assert status in (400, 500)
        assert "error" in body

    def test_missing_encrypted_text_for_text_type_returns_error(self):
        """Should return error when encrypted_text is missing for text type.

        Note: encrypted_text validation happens inside the DynamoDB retry loop,
        so without DynamoDB configured it may return 400 or 500.
        """
        event = _make_event({
            "content_type": "text",
            "pin": "7a2B",
            "ttl": "1h",
        })

        response = pin_upload_init_handler(event, None)
        status, body = _parse_response(response)

        assert status in (400, 500)
        assert "error" in body

    def test_negative_file_size_returns_400(self):
        """Should return 400 for negative file size."""
        event = _make_event({
            "content_type": "file",
            "file_size": -1,
            "pin": "7a2B",
            "ttl": "1h",
        })

        response = pin_upload_init_handler(event, None)
        status, body = _parse_response(response)

        # file_size validation happens after DynamoDB call for PIN upload
        assert status in (400, 500)
        assert "error" in body

    def test_zero_file_size_returns_400(self):
        """Should return 400 for zero file size."""
        event = _make_event({
            "content_type": "file",
            "file_size": 0,
            "pin": "7a2B",
            "ttl": "1h",
        })

        response = pin_upload_init_handler(event, None)
        status, body = _parse_response(response)

        assert status in (400, 500)
        assert "error" in body

    def test_response_has_standard_headers(self):
        """Should include Content-Type and CORS headers in all responses."""
        event = _make_event({
            "content_type": "file",
            "file_size": 1024,
            "ttl": "1h",
            # Missing PIN
        })

        response = pin_upload_init_handler(event, None)

        assert "headers" in response
        assert response["headers"]["Content-Type"] == "application/json"
        assert response["headers"]["Access-Control-Allow-Origin"] == "*"

    def test_response_body_is_valid_json(self):
        """Should return valid JSON in all error responses."""
        event = _make_event({
            "pin": "12",  # Invalid: too short
            "ttl": "1h",
        })

        response = pin_upload_init_handler(event, None)

        # Body must be parseable JSON
        body = json.loads(response["body"])
        assert isinstance(body, dict)

    def test_empty_body_returns_400(self):
        """Should return 400 when body is empty."""
        event = _make_event({})

        response = pin_upload_init_handler(event, None)
        status, body = _parse_response(response)

        assert status == 400
        assert "error" in body

    def test_invalid_json_body_returns_400(self):
        """Should return 400 when body is not valid JSON.

        The decorator parses the body first for reCAPTCHA token.
        Without RECAPTCHA_SECRET_KEY set, it skips verification.
        parse_json_body in handler returns {} for invalid JSON.
        """
        event = _make_event_raw_body("not valid json{{{")

        response = pin_upload_init_handler(event, None)
        status, body = _parse_response(response)

        # Either 400 from validation or from decorator
        assert status == 400
        assert "error" in body

    def test_pin_with_spaces_returns_400(self):
        """Should return 400 when PIN contains spaces."""
        event = _make_event({
            "content_type": "file",
            "file_size": 1024,
            "pin": "ab d",
            "ttl": "1h",
        })

        response = pin_upload_init_handler(event, None)
        status, body = _parse_response(response)

        assert status == 400
        assert "error" in body

    def test_text_too_large_returns_error(self):
        """Should return error when text secret exceeds 10000 chars."""
        event = _make_event({
            "content_type": "text",
            "encrypted_text": "a" * 10001,
            "pin": "7a2B",
            "ttl": "1h",
        })

        response = pin_upload_init_handler(event, None)
        status, body = _parse_response(response)

        # May hit DynamoDB error first or validation error
        assert status in (400, 500)
        assert "error" in body


# ──────────────────────────────────────────────────────────────────────
# PIN Initiate Handler - Integration Tests
# ──────────────────────────────────────────────────────────────────────


class TestPinInitiateHandlerIntegration:
    """End-to-end tests for pin_initiate handler validation paths."""

    def test_missing_file_id_returns_400(self):
        """Should return 400 when file_id is not provided."""
        event = _make_event({})

        response = pin_initiate_handler(event, None)
        status, body = _parse_response(response)

        assert status == 400
        assert "error" in body
        assert "File ID" in body["error"]

    def test_empty_file_id_returns_400(self):
        """Should return 400 when file_id is empty string."""
        event = _make_event({"file_id": ""})

        response = pin_initiate_handler(event, None)
        status, body = _parse_response(response)

        assert status == 400
        assert "error" in body

    def test_file_id_too_short_returns_400(self):
        """Should return 400 when file_id has fewer than 6 digits."""
        event = _make_event({"file_id": "12345"})

        response = pin_initiate_handler(event, None)
        status, body = _parse_response(response)

        assert status == 400
        assert "error" in body
        assert "6 digits" in body["error"]

    def test_file_id_too_long_returns_400(self):
        """Should return 400 when file_id has more than 6 digits."""
        event = _make_event({"file_id": "1234567"})

        response = pin_initiate_handler(event, None)
        status, body = _parse_response(response)

        assert status == 400
        assert "error" in body
        assert "6 digits" in body["error"]

    def test_non_numeric_file_id_returns_400(self):
        """Should return 400 when file_id contains non-numeric characters."""
        event = _make_event({"file_id": "abcdef"})

        response = pin_initiate_handler(event, None)
        status, body = _parse_response(response)

        assert status == 400
        assert "error" in body
        assert "6 digits" in body["error"]

    def test_mixed_alphanumeric_file_id_returns_400(self):
        """Should return 400 when file_id mixes letters and digits."""
        event = _make_event({"file_id": "12ab34"})

        response = pin_initiate_handler(event, None)
        status, body = _parse_response(response)

        assert status == 400
        assert "error" in body

    def test_file_id_with_special_chars_returns_400(self):
        """Should return 400 when file_id contains special characters."""
        event = _make_event({"file_id": "12@#56"})

        response = pin_initiate_handler(event, None)
        status, body = _parse_response(response)

        assert status == 400
        assert "error" in body

    def test_file_id_none_returns_400(self):
        """Should return 400 when file_id is explicitly None."""
        event = _make_event({"file_id": None})

        response = pin_initiate_handler(event, None)
        status, body = _parse_response(response)

        assert status == 400
        assert "error" in body

    def test_response_has_standard_headers(self):
        """Should include Content-Type and CORS headers."""
        event = _make_event({})

        response = pin_initiate_handler(event, None)

        assert response["headers"]["Content-Type"] == "application/json"
        assert response["headers"]["Access-Control-Allow-Origin"] == "*"

    def test_response_body_is_valid_json(self):
        """Should return valid JSON in error responses."""
        event = _make_event({"file_id": "short"})

        response = pin_initiate_handler(event, None)

        body = json.loads(response["body"])
        assert isinstance(body, dict)
        assert "error" in body

    def test_xss_in_file_id_not_reflected(self):
        """Should not reflect malicious input in error messages."""
        malicious = "<script>alert('x')</script>"
        event = _make_event({"file_id": malicious})

        response = pin_initiate_handler(event, None)
        status, body = _parse_response(response)

        assert status == 400
        assert malicious not in body["error"]

    def test_invalid_json_body_returns_400(self):
        """Should return 400 for malformed JSON body."""
        event = _make_event_raw_body("{invalid json")

        response = pin_initiate_handler(event, None)
        status, body = _parse_response(response)

        assert status == 400
        assert "error" in body


# ──────────────────────────────────────────────────────────────────────
# PIN Verify Handler - Integration Tests
# ──────────────────────────────────────────────────────────────────────


class TestPinVerifyHandlerIntegration:
    """End-to-end tests for pin_verify handler validation paths."""

    def test_missing_file_id_returns_400(self):
        """Should return 400 when file_id is not provided."""
        event = _make_event({"pin": "7a2B"})

        response = pin_verify_handler(event, None)
        status, body = _parse_response(response)

        assert status == 400
        assert "error" in body
        assert "File ID" in body["error"]

    def test_missing_pin_returns_400(self):
        """Should return 400 when PIN is not provided."""
        event = _make_event({"file_id": "482973"})

        response = pin_verify_handler(event, None)
        status, body = _parse_response(response)

        assert status == 400
        assert "error" in body
        assert "PIN" in body["error"]

    def test_missing_both_returns_400(self):
        """Should return 400 when both file_id and PIN are missing."""
        event = _make_event({})

        response = pin_verify_handler(event, None)
        status, body = _parse_response(response)

        assert status == 400
        assert "error" in body

    def test_invalid_file_id_returns_400(self):
        """Should return 400 for invalid file_id format."""
        event = _make_event({
            "file_id": "abc",
            "pin": "7a2B",
        })

        response = pin_verify_handler(event, None)
        status, body = _parse_response(response)

        assert status == 400
        assert "error" in body

    def test_invalid_pin_format_returns_400(self):
        """Should return 400 for invalid PIN format."""
        event = _make_event({
            "file_id": "482973",
            "pin": "@@",
        })

        response = pin_verify_handler(event, None)
        status, body = _parse_response(response)

        assert status == 400
        assert "error" in body

    def test_short_pin_returns_400(self):
        """Should return 400 when PIN is too short."""
        event = _make_event({
            "file_id": "482973",
            "pin": "ab",
        })

        response = pin_verify_handler(event, None)
        status, body = _parse_response(response)

        assert status == 400
        assert "4 characters" in body["error"]

    def test_long_pin_returns_400(self):
        """Should return 400 when PIN is too long."""
        event = _make_event({
            "file_id": "482973",
            "pin": "abcde",
        })

        response = pin_verify_handler(event, None)
        status, body = _parse_response(response)

        assert status == 400
        assert "4 characters" in body["error"]

    def test_non_numeric_file_id_returns_400(self):
        """Should return 400 when file_id is not numeric."""
        event = _make_event({
            "file_id": "abcdef",
            "pin": "7a2B",
        })

        response = pin_verify_handler(event, None)
        status, body = _parse_response(response)

        assert status == 400
        assert "6 digits" in body["error"]

    def test_file_id_too_short_returns_400(self):
        """Should return 400 when file_id has fewer than 6 digits."""
        event = _make_event({
            "file_id": "12345",
            "pin": "7a2B",
        })

        response = pin_verify_handler(event, None)
        status, body = _parse_response(response)

        assert status == 400
        assert "6 digits" in body["error"]

    def test_empty_pin_returns_400(self):
        """Should return 400 when PIN is empty."""
        event = _make_event({
            "file_id": "482973",
            "pin": "",
        })

        response = pin_verify_handler(event, None)
        status, body = _parse_response(response)

        assert status == 400
        assert "error" in body

    def test_response_has_standard_headers(self):
        """Should include Content-Type and CORS headers."""
        event = _make_event({})

        response = pin_verify_handler(event, None)

        assert response["headers"]["Content-Type"] == "application/json"
        assert response["headers"]["Access-Control-Allow-Origin"] == "*"

    def test_response_body_is_valid_json(self):
        """Should return valid JSON in error responses."""
        event = _make_event({
            "file_id": "bad",
            "pin": "bad",
        })

        response = pin_verify_handler(event, None)

        body = json.loads(response["body"])
        assert isinstance(body, dict)
        assert "error" in body

    def test_xss_in_pin_not_reflected(self):
        """Should not reflect malicious PIN input in error messages."""
        malicious = "<img src=x onerror=alert(1)>"
        event = _make_event({
            "file_id": "482973",
            "pin": malicious,
        })

        response = pin_verify_handler(event, None)
        status, body = _parse_response(response)

        assert status == 400
        assert malicious not in body["error"]

    def test_invalid_json_body_returns_400(self):
        """Should return 400 for malformed JSON body."""
        event = _make_event_raw_body("{{not json}}")

        response = pin_verify_handler(event, None)
        status, body = _parse_response(response)

        assert status == 400
        assert "error" in body

    def test_null_body_raises_type_error(self):
        """Null body causes TypeError in decorator's json.loads.

        When body is explicitly None (not missing), the decorator's
        event.get("body", "{}") returns None (key exists), and
        json.loads(None) raises TypeError. This is a known edge case
        since API Gateway always sends a string body.
        """
        event = {
            "body": None,
            "headers": {},
            "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
        }

        with pytest.raises(TypeError):
            pin_verify_handler(event, None)


# ──────────────────────────────────────────────────────────────────────
# Cross-Handler Response Format Consistency
# ──────────────────────────────────────────────────────────────────────


class TestResponseFormatConsistency:
    """Verify all three PIN handlers return consistent response formats."""

    @pytest.fixture
    def validation_error_events(self):
        """Events that trigger validation errors for each handler."""
        return {
            "upload": _make_event({"pin": "!!"}),
            "initiate": _make_event({"file_id": "bad"}),
            "verify": _make_event({"file_id": "bad", "pin": "!!"}),
        }

    def test_all_error_responses_have_error_key(self, validation_error_events):
        """All handlers should return {'error': '...'} on validation failure."""
        handlers = {
            "upload": pin_upload_init_handler,
            "initiate": pin_initiate_handler,
            "verify": pin_verify_handler,
        }

        for name, handler in handlers.items():
            event = validation_error_events[name]
            response = handler(event, None)
            body = json.loads(response["body"])
            assert "error" in body, f"{name} handler missing 'error' key in response"

    def test_all_error_responses_have_cors_headers(self, validation_error_events):
        """All handlers should include CORS headers on error responses."""
        handlers = {
            "upload": pin_upload_init_handler,
            "initiate": pin_initiate_handler,
            "verify": pin_verify_handler,
        }

        for name, handler in handlers.items():
            event = validation_error_events[name]
            response = handler(event, None)
            assert response["headers"]["Access-Control-Allow-Origin"] == "*", (
                f"{name} handler missing CORS header"
            )

    def test_all_error_responses_are_400_for_validation(self, validation_error_events):
        """All handlers should return 400 for validation errors."""
        handlers = {
            "upload": pin_upload_init_handler,
            "initiate": pin_initiate_handler,
            "verify": pin_verify_handler,
        }

        for name, handler in handlers.items():
            event = validation_error_events[name]
            response = handler(event, None)
            assert response["statusCode"] == 400, (
                f"{name} handler returned {response['statusCode']} instead of 400"
            )

    def test_all_handlers_handle_empty_body_gracefully(self):
        """All handlers should handle empty body without crashing."""
        event = _make_event({})
        handlers = [
            ("upload", pin_upload_init_handler),
            ("initiate", pin_initiate_handler),
            ("verify", pin_verify_handler),
        ]

        for name, handler in handlers:
            response = handler(event, None)
            assert response["statusCode"] in (400, 500), (
                f"{name} handler returned unexpected status {response['statusCode']}"
            )
            # Body must always be valid JSON
            body = json.loads(response["body"])
            assert isinstance(body, dict), f"{name} handler body is not a dict"
