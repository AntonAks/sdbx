"""Lambda function: Download file."""

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
from shared.json_helper import dumps as json_dumps
from shared.s3 import generate_download_url
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

        return _success_response({
            "download_url": download_url,
            "file_size": record["file_size"],
        })

    except ValidationError as e:
        logger.warning(f"Validation error: {e}")
        return _error_response(400, str(e))

    except FileNotFoundError as e:
        logger.info(f"File not found: {e}")
        return _error_response(404, "File not found")

    except FileAlreadyDownloadedError as e:
        logger.info(f"File already downloaded: {e}")
        return _error_response(410, "File already downloaded")

    except FileExpiredError as e:
        logger.info(f"File expired: {e}")
        return _error_response(410, "File expired")

    except Exception as e:
        logger.exception("Unexpected error in download")
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
