"""Standardized Lambda response helpers."""

from typing import Any, Optional

from shared.json_helper import dumps as json_dumps


# Standard CORS headers for all responses
STANDARD_HEADERS = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
}


def success_response(
    data: dict,
    status_code: int = 200,
    additional_headers: Optional[dict] = None,
) -> dict[str, Any]:
    """
    Build successful API response.

    Args:
        data: Response data to return
        status_code: HTTP status code (default: 200)
        additional_headers: Optional additional headers to include

    Returns:
        Lambda response dict with statusCode, headers, and body

    Example:
        >>> success_response({"file_id": "123", "size": 1024})
        {
            "statusCode": 200,
            "headers": {"Content-Type": "application/json", ...},
            "body": '{"file_id": "123", "size": 1024}'
        }
    """
    headers = STANDARD_HEADERS.copy()
    if additional_headers:
        headers.update(additional_headers)

    return {
        "statusCode": status_code,
        "headers": headers,
        "body": json_dumps(data),
    }


def error_response(
    message: str,
    status_code: int = 400,
    additional_headers: Optional[dict] = None,
) -> dict[str, Any]:
    """
    Build error API response.

    Args:
        message: Error message to return to client
        status_code: HTTP status code (default: 400)
        additional_headers: Optional additional headers to include

    Returns:
        Lambda response dict with statusCode, headers, and error body

    Example:
        >>> error_response("File not found", 404)
        {
            "statusCode": 404,
            "headers": {"Content-Type": "application/json", ...},
            "body": '{"error": "File not found"}'
        }
    """
    headers = STANDARD_HEADERS.copy()
    if additional_headers:
        headers.update(additional_headers)

    return {
        "statusCode": status_code,
        "headers": headers,
        "body": json_dumps({"error": message}),
    }


# Convenience functions for common HTTP status codes

def ok(data: dict, additional_headers: Optional[dict] = None) -> dict[str, Any]:
    """Return 200 OK response with data."""
    return success_response(data, 200, additional_headers)


def bad_request(message: str, additional_headers: Optional[dict] = None) -> dict[str, Any]:
    """Return 400 Bad Request error."""
    return error_response(message, 400, additional_headers)


def forbidden(message: str = "Forbidden", additional_headers: Optional[dict] = None) -> dict[str, Any]:
    """Return 403 Forbidden error."""
    return error_response(message, 403, additional_headers)


def not_found(message: str = "Not found", additional_headers: Optional[dict] = None) -> dict[str, Any]:
    """Return 404 Not Found error."""
    return error_response(message, 404, additional_headers)


def gone(message: str = "Resource no longer available", additional_headers: Optional[dict] = None) -> dict[str, Any]:
    """Return 410 Gone error."""
    return error_response(message, 410, additional_headers)


def internal_error(
    message: str = "Internal server error",
    additional_headers: Optional[dict] = None,
) -> dict[str, Any]:
    """Return 500 Internal Server Error."""
    return error_response(message, 500, additional_headers)
