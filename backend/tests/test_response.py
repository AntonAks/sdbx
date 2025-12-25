"""Unit tests for response module - NO MOCKS."""

import json
from decimal import Decimal

import pytest
from shared.response import (
    success_response,
    error_response,
    ok,
    bad_request,
    forbidden,
    not_found,
    gone,
    internal_error,
)


class TestSuccessResponse:
    """Test success_response function."""

    def test_basic_success(self):
        """Should return properly formatted success response."""
        data = {"message": "Success", "value": 123}
        response = success_response(data)

        assert response["statusCode"] == 200
        assert response["headers"]["Content-Type"] == "application/json"
        assert response["headers"]["Access-Control-Allow-Origin"] == "*"

        body = json.loads(response["body"])
        assert body == data

    def test_success_with_custom_status(self):
        """Should accept custom status code."""
        response = success_response({"created": True}, status_code=201)
        assert response["statusCode"] == 201

    def test_success_with_additional_headers(self):
        """Should merge additional headers."""
        response = success_response(
            {"data": "test"},
            additional_headers={"X-Custom-Header": "value"}
        )

        assert response["headers"]["X-Custom-Header"] == "value"
        assert response["headers"]["Content-Type"] == "application/json"
        assert response["headers"]["Access-Control-Allow-Origin"] == "*"

    def test_success_with_decimal_value(self):
        """Should handle Decimal types (from DynamoDB)."""
        data = {"count": Decimal("42"), "price": Decimal("19.99")}
        response = success_response(data)

        body = json.loads(response["body"])
        assert body["count"] == 42  # Converted to int
        assert body["price"] == 19.99  # Converted to float

    def test_success_with_nested_decimal(self):
        """Should handle nested Decimal values."""
        data = {
            "items": [
                {"id": "1", "count": Decimal("10")},
                {"id": "2", "count": Decimal("20")},
            ]
        }
        response = success_response(data)

        body = json.loads(response["body"])
        assert body["items"][0]["count"] == 10
        assert body["items"][1]["count"] == 20

    def test_success_preserves_standard_headers(self):
        """Should not override standard headers with additional headers."""
        response = success_response(
            {"data": "test"},
            additional_headers={"Content-Type": "text/plain"}  # Try to override
        )

        # Additional header should override (last write wins)
        assert response["headers"]["Content-Type"] == "text/plain"


class TestErrorResponse:
    """Test error_response function."""

    def test_basic_error(self):
        """Should return properly formatted error response."""
        response = error_response("Something went wrong")

        assert response["statusCode"] == 400  # Default
        assert response["headers"]["Content-Type"] == "application/json"
        assert response["headers"]["Access-Control-Allow-Origin"] == "*"

        body = json.loads(response["body"])
        assert body == {"error": "Something went wrong"}

    def test_error_with_custom_status(self):
        """Should accept custom status code."""
        response = error_response("Not found", status_code=404)
        assert response["statusCode"] == 404

    def test_error_with_additional_headers(self):
        """Should merge additional headers."""
        response = error_response(
            "Unauthorized",
            status_code=401,
            additional_headers={"WWW-Authenticate": "Bearer"}
        )

        assert response["headers"]["WWW-Authenticate"] == "Bearer"
        assert response["headers"]["Content-Type"] == "application/json"

    def test_error_message_in_body(self):
        """Should wrap error message in 'error' key."""
        response = error_response("Test error", 500)

        body = json.loads(response["body"])
        assert "error" in body
        assert body["error"] == "Test error"
        assert len(body) == 1  # Only 'error' key


class TestConvenienceFunctions:
    """Test convenience helper functions."""

    def test_ok(self):
        """Test ok() helper."""
        response = ok({"result": "success"})

        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        assert body["result"] == "success"

    def test_bad_request(self):
        """Test bad_request() helper."""
        response = bad_request("Invalid input")

        assert response["statusCode"] == 400
        body = json.loads(response["body"])
        assert body["error"] == "Invalid input"

    def test_forbidden(self):
        """Test forbidden() helper."""
        response = forbidden("Access denied")

        assert response["statusCode"] == 403
        body = json.loads(response["body"])
        assert body["error"] == "Access denied"

    def test_forbidden_default_message(self):
        """Test forbidden() with default message."""
        response = forbidden()

        assert response["statusCode"] == 403
        body = json.loads(response["body"])
        assert body["error"] == "Forbidden"

    def test_not_found(self):
        """Test not_found() helper."""
        response = not_found("Resource not found")

        assert response["statusCode"] == 404
        body = json.loads(response["body"])
        assert body["error"] == "Resource not found"

    def test_not_found_default_message(self):
        """Test not_found() with default message."""
        response = not_found()

        assert response["statusCode"] == 404
        body = json.loads(response["body"])
        assert body["error"] == "Not found"

    def test_gone(self):
        """Test gone() helper."""
        response = gone("File already downloaded")

        assert response["statusCode"] == 410
        body = json.loads(response["body"])
        assert body["error"] == "File already downloaded"

    def test_gone_default_message(self):
        """Test gone() with default message."""
        response = gone()

        assert response["statusCode"] == 410
        body = json.loads(response["body"])
        assert body["error"] == "Resource no longer available"

    def test_internal_error(self):
        """Test internal_error() helper."""
        response = internal_error("Database connection failed")

        assert response["statusCode"] == 500
        body = json.loads(response["body"])
        assert body["error"] == "Database connection failed"

    def test_internal_error_default_message(self):
        """Test internal_error() with default message."""
        response = internal_error()

        assert response["statusCode"] == 500
        body = json.loads(response["body"])
        assert body["error"] == "Internal server error"


class TestCORSHeaders:
    """Test CORS headers are always present."""

    def test_success_has_cors(self):
        """Success responses should have CORS headers."""
        response = success_response({"data": "test"})
        assert "Access-Control-Allow-Origin" in response["headers"]
        assert response["headers"]["Access-Control-Allow-Origin"] == "*"

    def test_error_has_cors(self):
        """Error responses should have CORS headers."""
        response = error_response("Error", 500)
        assert "Access-Control-Allow-Origin" in response["headers"]
        assert response["headers"]["Access-Control-Allow-Origin"] == "*"

    def test_all_helpers_have_cors(self):
        """All convenience functions should include CORS."""
        helpers = [
            ok({"test": 1}),
            bad_request("test"),
            forbidden(),
            not_found(),
            gone(),
            internal_error(),
        ]

        for response in helpers:
            assert "Access-Control-Allow-Origin" in response["headers"]
            assert response["headers"]["Access-Control-Allow-Origin"] == "*"


class TestResponseEdgeCases:
    """Test edge cases and special characters."""

    def test_unicode_in_success(self):
        """Should handle Unicode characters."""
        data = {"message": "Hello 世界 🌍"}
        response = success_response(data)

        body = json.loads(response["body"])
        assert body["message"] == "Hello 世界 🌍"

    def test_unicode_in_error(self):
        """Should handle Unicode in error messages."""
        response = error_response("Erreur: échec 🚫")

        body = json.loads(response["body"])
        assert body["error"] == "Erreur: échec 🚫"

    def test_empty_data(self):
        """Should handle empty data dict."""
        response = success_response({})

        body = json.loads(response["body"])
        assert body == {}

    def test_nested_data(self):
        """Should handle deeply nested data."""
        data = {
            "level1": {
                "level2": {
                    "level3": {
                        "value": "deep"
                    }
                }
            }
        }
        response = success_response(data)

        body = json.loads(response["body"])
        assert body["level1"]["level2"]["level3"]["value"] == "deep"

    def test_list_in_data(self):
        """Should handle lists in data."""
        data = {"items": [1, 2, 3, 4, 5]}
        response = success_response(data)

        body = json.loads(response["body"])
        assert body["items"] == [1, 2, 3, 4, 5]

    def test_special_characters_in_error(self):
        """Should handle special characters in error messages."""
        response = error_response("Error: <script>alert('xss')</script>")

        body = json.loads(response["body"])
        # Should be properly escaped in JSON
        assert "<script>" in body["error"]

    def test_very_long_error_message(self):
        """Should handle very long error messages."""
        long_message = "A" * 10000
        response = error_response(long_message)

        body = json.loads(response["body"])
        assert len(body["error"]) == 10000

    def test_null_values_in_data(self):
        """Should handle None/null values."""
        data = {"value": None, "count": 0, "flag": False}
        response = success_response(data)

        body = json.loads(response["body"])
        assert body["value"] is None
        assert body["count"] == 0
        assert body["flag"] is False
