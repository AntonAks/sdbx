"""Lambda function: Report abuse."""

import json
import logging
import os
from typing import Any

from shared.dynamo import get_file_record, increment_report_count
from shared.exceptions import ValidationError
from shared.response import error_response, success_response
from shared.security import verify_cloudfront_origin, verify_recaptcha
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
        # Verify request comes from CloudFront
        if not verify_cloudfront_origin(event):
            return error_response('Direct API access not allowed', 403)

        # Parse request
        file_id = event.get("pathParameters", {}).get("file_id")
        body = json.loads(event.get("body", "{}"))
        reason = body.get("reason", "")
        recaptcha_token = body.get("recaptcha_token")

        # Verify reCAPTCHA token
        source_ip = event.get("requestContext", {}).get("identity", {}).get("sourceIp")
        is_valid, score, error_msg = verify_recaptcha(recaptcha_token, source_ip)

        if not is_valid:
            logger.warning(f"reCAPTCHA verification failed for abuse report: {error_msg} (score: {score})")
            return error_response(error_msg or "Bot activity detected", 403)

        logger.info(f"reCAPTCHA verification succeeded for abuse report with score: {score}")

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
