"""Lambda function: Initialize PIN-based file upload."""

import hashlib
import logging
import os
import time
from typing import Any

from shared.constants import (
    ACCESS_MODE_PIN,
    TTL_TO_SECONDS,
    UPLOAD_URL_EXPIRY_SECONDS,
)
from shared.dynamo import create_pin_file_record
from shared.exceptions import ValidationError
from shared.pin_utils import generate_pin_file_id, generate_salt, hash_pin
from shared.request_helpers import get_source_ip, parse_json_body
from shared.response import error_response, success_response
from shared.s3 import generate_upload_url
from shared.security import require_cloudfront_and_recaptcha
from shared.validation import validate_file_size, validate_pin, validate_ttl

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Environment variables
BUCKET_NAME = os.environ.get("BUCKET_NAME")
TABLE_NAME = os.environ.get("TABLE_NAME")

# Maximum retries for generating a unique 6-digit file ID
MAX_ID_RETRIES = 5


def ttl_to_seconds(ttl) -> int:
    """
    Convert TTL value to seconds.

    Args:
        ttl: Either a preset string ("1h", "12h", "24h") or minutes (int/float)

    Returns:
        TTL in seconds
    """
    if isinstance(ttl, str) and ttl in TTL_TO_SECONDS:
        return TTL_TO_SECONDS[ttl]

    # Numeric TTL is in minutes, convert to seconds
    return int(ttl) * 60


@require_cloudfront_and_recaptcha
def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """
    Initialize PIN-based file or text upload.

    Security verification (CloudFront origin + reCAPTCHA) is handled by decorator.

    Expected request body (file):
    {
        "content_type": "file",
        "file_size": 1024,
        "pin": "7a2B",
        "ttl": "1h",
        "recaptcha_token": "token"
    }

    Expected request body (text):
    {
        "content_type": "text",
        "encrypted_text": "base64-encrypted-text",
        "pin": "7a2B",
        "ttl": "1h",
        "recaptcha_token": "token"
    }

    Returns:
    {
        "file_id": "123456",        // 6-digit numeric ID
        "upload_url": "presigned",  // Only for files
        "expires_at": 1234567890
    }
    """
    try:
        # Parse request body
        body = parse_json_body(event)
        content_type = body.get("content_type", "file")
        ttl = body.get("ttl")
        pin = body.get("pin")
        file_name = body.get("file_name", "")

        # Validate inputs
        validate_ttl(ttl)
        validate_pin(pin)

        # Generate salt and hash the PIN (PIN itself is never stored or logged)
        salt = generate_salt()
        pin_hash = hash_pin(pin, salt)

        # Calculate expiration timestamp
        ttl_seconds = ttl_to_seconds(ttl)
        expires_at = int(time.time()) + ttl_seconds

        # Hash IP address (privacy)
        source_ip = get_source_ip(event)
        ip_hash = hashlib.sha256(source_ip.encode()).hexdigest()

        # Retry loop for 6-digit ID collisions
        for attempt in range(MAX_ID_RETRIES):
            candidate_id = generate_pin_file_id()
            try:
                if content_type == "text":
                    encrypted_text = body.get("encrypted_text")
                    if not encrypted_text:
                        raise ValidationError("encrypted_text is required for text secrets")
                    if len(encrypted_text) > 10000:
                        raise ValidationError("Text secret too large")

                    create_pin_file_record(
                        table_name=TABLE_NAME,
                        file_id=candidate_id,
                        file_size=len(encrypted_text),
                        expires_at=expires_at,
                        ip_hash=ip_hash,
                        pin_hash=pin_hash,
                        salt=salt,
                        content_type="text",
                        encrypted_text=encrypted_text,
                    )

                    logger.info(f"PIN text created: file_id={candidate_id}, ttl={ttl}")

                    return success_response({
                        "file_id": candidate_id,
                        "salt": salt,
                        "expires_at": expires_at,
                    })

                else:
                    file_size = body.get("file_size")
                    validate_file_size(file_size)
                    s3_key = f"files/{candidate_id}"

                    create_pin_file_record(
                        table_name=TABLE_NAME,
                        file_id=candidate_id,
                        file_size=file_size,
                        expires_at=expires_at,
                        ip_hash=ip_hash,
                        pin_hash=pin_hash,
                        salt=salt,
                        content_type="file",
                        s3_key=s3_key,
                        file_name=file_name,
                    )

                    upload_url = generate_upload_url(
                        bucket_name=BUCKET_NAME,
                        s3_key=s3_key,
                        expires_in=UPLOAD_URL_EXPIRY_SECONDS,
                    )

                    logger.info(
                        f"PIN file upload init: file_id={candidate_id}, "
                        f"size={file_size}, ttl={ttl}"
                    )

                    return success_response({
                        "file_id": candidate_id,
                        "upload_url": upload_url,
                        "salt": salt,
                        "expires_at": expires_at,
                    })

            except ValueError as e:
                if "already exists" in str(e):
                    logger.warning(f"PIN file ID collision: {candidate_id}, retrying...")
                    continue
                raise

        # Exhausted all retries
        logger.error("Failed to generate unique PIN file ID after max retries")
        return error_response("Failed to generate unique file ID. Please try again.", 500)

    except ValidationError as e:
        logger.warning(f"Validation error: {e}")
        return error_response(str(e), 400)

    except Exception as e:
        logger.exception("Unexpected error in pin_upload_init")
        return error_response("Internal server error", 500)
