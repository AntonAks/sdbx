"""Lambda function: Report abuse."""

import json
import logging
import os
from typing import Any

from shared.constants import AUTO_DELETE_THRESHOLD
from shared.dynamo import get_file_record, increment_report_count
from shared.exceptions import ValidationError
from shared.request_helpers import get_path_parameter, parse_json_body
from shared.response import error_response, success_response
from shared.security import require_cloudfront_and_recaptcha
from shared.validation import validate_file_id

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Environment variables
TABLE_NAME = os.environ.get("TABLE_NAME")


@require_cloudfront_and_recaptcha
def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """
    Report file for abuse.

    Security verification (CloudFront origin + reCAPTCHA) is handled by decorator.

    If report count reaches threshold, file should be reviewed/deleted.
    """
    try:
        # Parse request
        file_id = get_path_parameter(event, "file_id")
        body = parse_json_body(event)
        reason = body.get("reason", "")

        # Validate input
        validate_file_id(file_id)

        # Check if file exists
        record = get_file_record(TABLE_NAME, file_id)
        if not record:
            return error_response("File not found", 404)

        # Increment report count
        new_count = increment_report_count(TABLE_NAME, file_id)

        logger.warning(
            json.dumps({
                "action": "abuse_reported",
                "file_id": file_id,
                "reason": reason,
                "report_count": new_count,
                "recaptcha_score": event.get('_recaptcha_score', 'N/A'),
            })
        )

        # TODO: If count >= threshold, trigger admin review or auto-delete
        if new_count >= AUTO_DELETE_THRESHOLD:
            logger.critical(
                f"File {file_id} reached abuse threshold: {new_count} reports"
            )

        return success_response({
            "message": "Report submitted successfully",
            "report_count": new_count,
        })

    except ValidationError as e:
        logger.warning(f"Validation error: {e}")
        return error_response(str(e), 400)

    except Exception as e:
        logger.exception("Unexpected error in report_abuse")
        return error_response("Internal server error", 500)
