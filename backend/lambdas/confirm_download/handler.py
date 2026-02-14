"""Lambda function: Confirm download completion."""

import logging
import os
from typing import Any

from shared.dynamo import confirm_download
from shared.exceptions import (
    FileAlreadyDownloadedError,
    FileNotFoundError,
    ValidationError,
)
from shared.request_helpers import get_path_parameter
from shared.response import error_response, success_response
from shared.security import require_cloudfront_only
from shared.validation import validate_file_id

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Environment variables
TABLE_NAME = os.environ.get("TABLE_NAME")


@require_cloudfront_only
def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """
    Confirm successful download of file or text secret.

    Security verification (CloudFront origin) is handled by decorator.
    This endpoint should be called by the frontend after successfully
    downloading and decrypting the content.

    This marks the file as truly downloaded and increments statistics.
    """
    try:
        # Extract file ID from path
        file_id = get_path_parameter(event, "file_id")

        # Validate input
        validate_file_id(file_id)

        # Confirm download (mark as downloaded)
        record = confirm_download(TABLE_NAME, file_id)

        logger.info(f"Download confirmed: file_id={file_id}")

        return success_response({
            "message": "Download confirmed",
            "file_id": file_id,
        })

    except ValidationError as e:
        logger.warning(f"Validation error: {e}")
        return error_response(str(e), 400)

    except FileNotFoundError as e:
        logger.info(f"File not found: {e}")
        return error_response("File not found or no active reservation", 404)

    except FileAlreadyDownloadedError as e:
        logger.info(f"File already downloaded: {e}")
        return error_response("Download already confirmed", 410)

    except Exception as e:
        logger.exception("Unexpected error in confirm download")
        return error_response("Internal server error", 500)
