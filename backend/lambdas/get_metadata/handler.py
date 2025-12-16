"""Lambda function: Get file metadata."""

import logging
import os
import time
from typing import Any

from shared.dynamo import get_file_record
from shared.exceptions import ValidationError
from shared.json_helper import dumps as json_dumps
from shared.security import verify_cloudfront_origin, build_error_response
from shared.validation import validate_file_id

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Environment variables
TABLE_NAME = os.environ.get("TABLE_NAME")


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """
    Get file metadata.

    Returns file info if available, 404 if not found or expired.
    """
    try:
        # Verify request comes from CloudFront
        if not verify_cloudfront_origin(event):
            return build_error_response(403, 'Direct API access not allowed')

        # Extract file ID from path
        file_id = event.get("pathParameters", {}).get("file_id")

        # Validate input
        validate_file_id(file_id)

        # Get file record
        record = get_file_record(TABLE_NAME, file_id)

        if not record:
            return _error_response(404, "File not found")

        # Check if expired (DynamoDB TTL can take up to 48h)
        current_time = int(time.time())
        if record.get("expires_at", 0) <= current_time:
            return _error_response(410, "File expired")

        # Return metadata
        return _success_response({
            "file_id": record["file_id"],
            "file_size": record["file_size"],
            "available": not record.get("downloaded", False),
            "expires_at": record["expires_at"],
        })

    except ValidationError as e:
        logger.warning(f"Validation error: {e}")
        return _error_response(400, str(e))

    except Exception as e:
        logger.exception(f"Unexpected error in get_metadata")
        return _error_response(500, "Internal server error")


def _success_response(data: dict) -> dict[str, Any]:
    """Build successful API response."""
    return {
        "statusCode": 200,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
        },
        "body": json_dumps(data),
    }


def _error_response(status: int, message: str) -> dict[str, Any]:
    """Build error API response."""
    return {
        "statusCode": status,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
        },
        "body": json_dumps({"error": message}),
    }
