"""Lambda function: Download file."""

import logging
import os
from typing import Any

from shared.constants import DOWNLOAD_URL_EXPIRY_SECONDS
from shared.dynamo import increment_download_counter, mark_downloaded
from shared.exceptions import (
    FileAlreadyDownloadedError,
    FileExpiredError,
    FileNotFoundError,
    ValidationError,
)
from shared.request_helpers import get_path_parameter
from shared.response import error_response, success_response
from shared.s3 import generate_download_url
from shared.security import require_cloudfront_and_recaptcha
from shared.validation import validate_file_id

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Environment variables
BUCKET_NAME = os.environ.get("BUCKET_NAME")
TABLE_NAME = os.environ.get("TABLE_NAME")


@require_cloudfront_and_recaptcha
def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """
    Mark file as downloaded and return download URL.

    Security verification (CloudFront origin + reCAPTCHA) is handled by decorator.

    This uses atomic DynamoDB conditional update to ensure
    each file can only be downloaded once.
    """
    try:
        # Extract file ID from path
        file_id = get_path_parameter(event, "file_id")

        # Validate input
        validate_file_id(file_id)

        # Atomically mark as downloaded
        record = mark_downloaded(TABLE_NAME, file_id)

        # Increment global download counter and total bytes
        try:
            increment_download_counter(TABLE_NAME, file_size=record["file_size"])
        except Exception as e:
            # Don't fail the download if counter increment fails
            logger.warning(f"Failed to increment download counter: {e}")

        # Generate presigned download URL
        download_url = generate_download_url(
            bucket_name=BUCKET_NAME,
            s3_key=record["s3_key"],
            expires_in=DOWNLOAD_URL_EXPIRY_SECONDS,
        )

        logger.info(f"File download initiated: file_id={file_id}, score={event.get('_recaptcha_score', 'N/A')}")

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
