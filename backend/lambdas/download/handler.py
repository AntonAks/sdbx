"""Lambda function: Download file."""

import json
import logging
import os
from typing import Any

from shared.dynamo import mark_downloaded
from shared.exceptions import (
    FileAlreadyDownloadedError,
    FileExpiredError,
    FileNotFoundError,
    ValidationError,
)
from shared.response import error_response, success_response
from shared.s3 import generate_download_url
from shared.security import verify_cloudfront_origin, verify_recaptcha
from shared.validation import validate_file_id

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Environment variables
BUCKET_NAME = os.environ.get("BUCKET_NAME")
TABLE_NAME = os.environ.get("TABLE_NAME")


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """
    Mark file as downloaded and return download URL.

    This uses atomic DynamoDB conditional update to ensure
    each file can only be downloaded once.
    """
    try:
        # Verify request comes from CloudFront
        if not verify_cloudfront_origin(event):
            return error_response('Direct API access not allowed', 403)

        # Parse request body
        body = json.loads(event.get("body", "{}"))
        recaptcha_token = body.get("recaptcha_token")

        # Verify reCAPTCHA token
        source_ip = event.get("requestContext", {}).get("identity", {}).get("sourceIp")
        is_valid, score, error_msg = verify_recaptcha(recaptcha_token, source_ip)

        if not is_valid:
            logger.warning(f"reCAPTCHA verification failed for download: {error_msg} (score: {score})")
            return error_response(error_msg or "Bot activity detected", 403)

        logger.info(f"reCAPTCHA verification succeeded for download with score: {score}")

        # Extract file ID from path
        file_id = event.get("pathParameters", {}).get("file_id")

        # Validate input
        validate_file_id(file_id)

        # Atomically mark as downloaded
        record = mark_downloaded(TABLE_NAME, file_id)

        # Generate presigned download URL (5 minutes)
        download_url = generate_download_url(
            bucket_name=BUCKET_NAME,
            s3_key=record["s3_key"],
            expires_in=300,
        )

        logger.info(f"File download initiated: {file_id}")

        return success_response({
            "download_url": download_url,
            "file_size": record["file_size"],
        })

    except ValidationError as e:
        logger.warning(f"Validation error: {e}")
        return error_response(str(e), 400)

    except FileNotFoundError as e:
        logger.info(f"File not found: {e}")
        return error_response("File not found", 404)

    except FileAlreadyDownloadedError as e:
        logger.info(f"File already downloaded: {e}")
        return error_response("File already downloaded", 410)

    except FileExpiredError as e:
        logger.info(f"File expired: {e}")
        return error_response("File expired", 410)

    except Exception as e:
        logger.exception("Unexpected error in download")
        return error_response("Internal server error", 500)
