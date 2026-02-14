"""Lambda function: Download file."""

import logging
import os
from typing import Any

from shared.constants import ACCESS_MODE_MULTI, DOWNLOAD_URL_EXPIRY_SECONDS
from shared.dynamo import get_file_record, increment_vault_download, reserve_download
from shared.exceptions import (
    FileAlreadyDownloadedError,
    FileExpiredError,
    FileNotFoundError,
    FileReservedError,
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
    Reserve file or text secret for download and return content.

    Security verification (CloudFront origin + reCAPTCHA) is handled by decorator.

    For files: Returns presigned S3 download URL
    For text: Returns encrypted text directly

    For one-time access:
    - Uses atomic DynamoDB conditional update to reserve the download.
    - The frontend must call /confirm endpoint after successful download.

    For multi-access (vault):
    - Increments download count (no reservation needed)
    - No confirmation required
    - Can be downloaded unlimited times until TTL expires
    """
    try:
        # Extract file ID from path
        file_id = get_path_parameter(event, "file_id")

        # Validate input
        validate_file_id(file_id)

        # First, get the record to check access mode
        initial_record = get_file_record(TABLE_NAME, file_id)
        if not initial_record:
            raise FileNotFoundError("File not found")

        access_mode = initial_record.get("access_mode", "one_time")

        # Handle based on access mode
        if access_mode == ACCESS_MODE_MULTI:
            # Vault (multi-access) - just increment download count
            record = increment_vault_download(TABLE_NAME, file_id)
        else:
            # One-time access - atomically reserve for download
            record = reserve_download(TABLE_NAME, file_id)

        # Check content type and return appropriate response
        content_type = record.get("content_type", "file")

        if content_type == "text":
            # Text secret - return encrypted text directly
            log_suffix = f"score={event.get('_recaptcha_score', 'N/A')}"
            if access_mode == ACCESS_MODE_MULTI:
                logger.info(f"Vault text download #{record.get('download_count', 1)}: file_id={file_id}, {log_suffix}")
            else:
                logger.info(f"Text secret download reserved: file_id={file_id}, {log_suffix}")

            return success_response({
                "content_type": "text",
                "encrypted_text": record["encrypted_text"],
                "file_size": record["file_size"],
                "access_mode": access_mode,
            })

        else:
            # File - generate presigned download URL
            download_url = generate_download_url(
                bucket_name=BUCKET_NAME,
                s3_key=record["s3_key"],
                expires_in=DOWNLOAD_URL_EXPIRY_SECONDS,
            )

            log_suffix = f"score={event.get('_recaptcha_score', 'N/A')}"
            if access_mode == ACCESS_MODE_MULTI:
                logger.info(f"Vault file download #{record.get('download_count', 1)}: file_id={file_id}, {log_suffix}")
            else:
                logger.info(f"File download reserved: file_id={file_id}, {log_suffix}")

            return success_response({
                "content_type": "file",
                "download_url": download_url,
                "file_size": record["file_size"],
                "access_mode": access_mode,
            })

    except ValidationError as e:
        logger.warning(f"Validation error: {e}")
        return error_response(str(e), 400)

    except FileNotFoundError as e:
        logger.info(f"File not found: {e}")
        return error_response("File not found", 404)

    except FileReservedError as e:
        logger.info(f"File currently reserved: {e}")
        return error_response("File is currently being downloaded", 409)

    except FileAlreadyDownloadedError as e:
        logger.info(f"File already downloaded: {e}")
        return error_response("File already downloaded", 410)

    except FileExpiredError as e:
        logger.info(f"File expired: {e}")
        return error_response("File expired", 410)

    except Exception as e:
        logger.exception("Unexpected error in download")
        return error_response("Internal server error", 500)
