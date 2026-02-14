"""Lambda function: Initiate PIN download session."""

import logging
import os
from typing import Any

from shared.dynamo import initiate_pin_session
from shared.exceptions import (
    FileAlreadyDownloadedError,
    FileExpiredError,
    FileLockedException,
    FileNotFoundError,
    ValidationError,
)
from shared.request_helpers import parse_json_body
from shared.response import error_response, success_response
from shared.security import require_cloudfront_and_recaptcha
from shared.validation import validate_pin_file_id

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

TABLE_NAME = os.environ.get("TABLE_NAME")


@require_cloudfront_and_recaptcha
def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """
    Initiate a 60-second PIN entry session.

    Request: { file_id: "482973", recaptcha_token: "..." }
    Response: { message, session_expires, attempts_left }
    """
    try:
        body = parse_json_body(event)
        file_id = body.get("file_id")
        validate_pin_file_id(file_id)

        result = initiate_pin_session(TABLE_NAME, file_id)

        logger.info(f"PIN session initiated: file_id={file_id}")

        return success_response({
            "message": "Session started. Enter PIN within 60 seconds",
            "session_expires": result["session_expires"],
            "attempts_left": result["attempts_left"],
        })

    except ValidationError as e:
        logger.warning(f"Validation error: {e}")
        return error_response(str(e), 400)
    except FileNotFoundError:
        return error_response("File not found", 404)
    except FileExpiredError:
        return error_response("File has expired", 410)
    except FileAlreadyDownloadedError:
        return error_response("File has already been downloaded", 410)
    except FileLockedException as e:
        return error_response(str(e), 423)
    except Exception as e:
        logger.exception("Unexpected error in pin_initiate")
        return error_response("Internal server error", 500)
