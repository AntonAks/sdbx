"""Lambda function: Get file metadata."""

import logging
import os
import time
from typing import Any

from shared.dynamo import get_file_record
from shared.exceptions import ValidationError
from shared.response import error_response, success_response
from shared.security import verify_cloudfront_origin
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
            return error_response('Direct API access not allowed', 403)

        # Extract file ID from path
        file_id = event.get("pathParameters", {}).get("file_id")

        # Validate input
        validate_file_id(file_id)

        # Get file record
        record = get_file_record(TABLE_NAME, file_id)

        if not record:
            return error_response("File not found", 404)

        # Check if expired (DynamoDB TTL can take up to 48h)
        current_time = int(time.time())
        if record.get("expires_at", 0) <= current_time:
            return error_response("File expired", 410)

        # Return metadata
        return success_response({
            "file_id": record["file_id"],
            "file_size": record["file_size"],
            "available": not record.get("downloaded", False),
            "expires_at": record["expires_at"],
        })

    except ValidationError as e:
        logger.warning(f"Validation error: {e}")
        return error_response(str(e), 400)

    except Exception as e:
        logger.exception(f"Unexpected error in get_metadata")
        return error_response("Internal server error", 500)
