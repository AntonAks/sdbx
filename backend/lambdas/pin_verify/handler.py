"""Lambda function: Verify PIN and initiate download."""

import logging
import os
from typing import Any

from shared.constants import DOWNLOAD_URL_EXPIRY_SECONDS
from shared.dynamo import increment_download_counter, verify_pin_and_download
from shared.exceptions import (
    FileAlreadyDownloadedError,
    FileExpiredError,
    FileLockedException,
    FileNotFoundError,
    SessionExpiredError,
    ValidationError,
)
from shared.request_helpers import parse_json_body
from shared.response import error_response, success_response
from shared.s3 import generate_download_url
from shared.security import require_cloudfront_and_recaptcha
from shared.validation import validate_pin, validate_pin_file_id

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

BUCKET_NAME = os.environ.get("BUCKET_NAME")
TABLE_NAME = os.environ.get("TABLE_NAME")


@require_cloudfront_and_recaptcha
def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """
    Verify PIN and return download content.

    Request: { file_id: "482973", pin: "7a2B", recaptcha_token: "..." }
    Response (success): { content_type, download_url/encrypted_text, salt, file_size }
    """
    try:
        body = parse_json_body(event)
        file_id = body.get("file_id")
        pin = body.get("pin")

        validate_pin_file_id(file_id)
        validate_pin(pin)

        record = verify_pin_and_download(TABLE_NAME, file_id, pin)

        # Increment global stats (non-blocking)
        try:
            increment_download_counter(TABLE_NAME, file_size=record.get("file_size", 0))
        except Exception as stats_err:
            logger.warning(f"Failed to increment stats for PIN download: {stats_err}")

        content_type = record.get("content_type", "file")
        salt = record.get("salt")

        file_name = record.get("file_name", "")

        if content_type == "text":
            logger.info(f"PIN text download: file_id={file_id}")
            return success_response({
                "content_type": "text",
                "encrypted_text": record["encrypted_text"],
                "salt": salt,
                "file_size": record["file_size"],
                "file_name": file_name,
            })
        else:
            download_url = generate_download_url(
                bucket_name=BUCKET_NAME,
                s3_key=record["s3_key"],
                expires_in=DOWNLOAD_URL_EXPIRY_SECONDS,
            )
            logger.info(f"PIN file download: file_id={file_id}")
            return success_response({
                "content_type": "file",
                "download_url": download_url,
                "salt": salt,
                "file_size": record["file_size"],
                "file_name": file_name,
            })

    except ValidationError as e:
        msg = str(e)
        if "attempts left" in msg:
            return error_response(msg, 401)
        return error_response(msg, 400)
    except FileNotFoundError:
        return error_response("File not found", 404)
    except SessionExpiredError as e:
        return error_response(str(e), 408)
    except FileAlreadyDownloadedError:
        return error_response("File has already been downloaded", 410)
    except FileExpiredError:
        return error_response("File has expired", 410)
    except FileLockedException as e:
        return error_response(str(e), 423)
    except Exception as e:
        logger.exception("Unexpected error in pin_verify")
        return error_response("Internal server error", 500)
