"""Lambda function: Report abuse."""

import json
import logging
import os
from typing import Any

from shared.dynamo import get_file_record, increment_report_count
from shared.exceptions import ValidationError
from shared.validation import validate_file_id

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Environment variables
TABLE_NAME = os.environ.get("TABLE_NAME")
AUTO_DELETE_THRESHOLD = 3  # Auto-delete after 3 reports


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """
    Report file for abuse.

    If report count reaches threshold, file should be reviewed/deleted.
    """
    try:
        # Parse request
        file_id = event.get("pathParameters", {}).get("file_id")
        body = json.loads(event.get("body", "{}"))
        reason = body.get("reason", "")

        # Validate input
        validate_file_id(file_id)

        # Check if file exists
        record = get_file_record(TABLE_NAME, file_id)
        if not record:
            return _error_response(404, "File not found")

        # Increment report count
        new_count = increment_report_count(TABLE_NAME, file_id)

        logger.warning(
            json.dumps({
                "action": "abuse_reported",
                "file_id": file_id,
                "reason": reason,
                "report_count": new_count,
            })
        )

        # TODO: If count >= threshold, trigger admin review or auto-delete
        if new_count >= AUTO_DELETE_THRESHOLD:
            logger.critical(
                f"File {file_id} reached abuse threshold: {new_count} reports"
            )

        return _success_response({
            "message": "Report submitted successfully",
            "report_count": new_count,
        })

    except ValidationError as e:
        logger.warning(f"Validation error: {e}")
        return _error_response(400, str(e))

    except Exception as e:
        logger.exception("Unexpected error in report_abuse")
        return _error_response(500, "Internal server error")


def _success_response(data: dict) -> dict[str, Any]:
    """Build successful API response."""
    return {
        "statusCode": 200,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
        },
        "body": json.dumps(data),
    }


def _error_response(status: int, message: str) -> dict[str, Any]:
    """Build error API response."""
    return {
        "statusCode": status,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
        },
        "body": json.dumps({"error": message}),
    }
