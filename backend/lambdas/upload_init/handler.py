"""Lambda function: Initialize file upload."""

import logging
import os
import time
import uuid
from typing import Any

from shared.constants import (
    ACCESS_MODE_MULTI,
    ACCESS_MODE_ONE_TIME,
    TTL_TO_SECONDS,
    UPLOAD_URL_EXPIRY_SECONDS,
)
from shared.dynamo import create_file_record
from shared.exceptions import ValidationError
from shared.request_helpers import get_source_ip, parse_json_body
from shared.response import error_response, success_response
from shared.s3 import generate_upload_url
from shared.security import hash_ip_secure, require_cloudfront_and_recaptcha
from shared.validation import (
    validate_access_mode,
    validate_encrypted_key,
    validate_file_size,
    validate_salt,
    validate_ttl,
)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Environment variables
BUCKET_NAME = os.environ.get("BUCKET_NAME")
TABLE_NAME = os.environ.get("TABLE_NAME")


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
    Initialize file or text secret upload.

    Security verification (CloudFront origin + reCAPTCHA) is handled by decorator.

    Expected request body (file):
    {
        "content_type": "file",
        "file_size": 1024,
        "ttl": "1h",
        "recaptcha_token": "token"
    }

    Expected request body (text):
    {
        "content_type": "text",
        "encrypted_text": "base64-encrypted-text",
        "ttl": "1h",
        "recaptcha_token": "token"
    }

    Expected request body (vault file):
    {
        "content_type": "file",
        "file_size": 1024,
        "ttl": "1h",
        "access_mode": "multi",
        "salt": "base64-salt",
        "encrypted_key": "base64-encrypted-key",
        "recaptcha_token": "token"
    }

    Expected request body (vault text):
    {
        "content_type": "text",
        "encrypted_text": "base64-encrypted-text",
        "ttl": "1h",
        "access_mode": "multi",
        "salt": "base64-salt",
        "encrypted_key": "base64-encrypted-key",
        "recaptcha_token": "token"
    }

    Returns:
    {
        "file_id": "uuid",
        "upload_url": "presigned-s3-url",  // Only for files
        "expires_at": 1234567890
    }
    """
    try:
        # Parse request body
        body = parse_json_body(event)
        content_type = body.get("content_type", "file")
        ttl = body.get("ttl")
        access_mode = body.get("access_mode", ACCESS_MODE_ONE_TIME)

        # Validate TTL and access mode
        validate_ttl(ttl)
        validate_access_mode(access_mode)

        # Validate vault-specific fields if multi-access mode
        salt = None
        encrypted_key = None
        if access_mode == ACCESS_MODE_MULTI:
            salt = body.get("salt")
            encrypted_key = body.get("encrypted_key")
            validate_salt(salt)
            validate_encrypted_key(encrypted_key)

        # Generate unique ID
        file_id = str(uuid.uuid4())

        # Calculate expiration timestamp
        ttl_seconds = ttl_to_seconds(ttl)
        expires_at = int(time.time()) + ttl_seconds

        # Hash IP address (privacy)
        source_ip = get_source_ip(event)
        ip_hash = hash_ip_secure(source_ip)

        # Handle based on content type
        if content_type == "text":
            # Text secret
            encrypted_text = body.get("encrypted_text")
            if not encrypted_text:
                raise ValidationError("encrypted_text is required for text secrets")

            # Validate text length (base64 encoded)
            # For vault, allow larger text (10000 chars)
            max_text_size = 100000 if access_mode == ACCESS_MODE_MULTI else 10000
            if len(encrypted_text) > max_text_size:
                raise ValidationError("Text secret too large")

            # Create DynamoDB record with encrypted text
            create_file_record(
                table_name=TABLE_NAME,
                file_id=file_id,
                file_size=len(encrypted_text),
                expires_at=expires_at,
                ip_hash=ip_hash,
                content_type="text",
                encrypted_text=encrypted_text,
                access_mode=access_mode,
                salt=salt,
                encrypted_key=encrypted_key,
            )

            logger.info(f"Text secret created: file_id={file_id}, size={len(encrypted_text)}, ttl={ttl}, access_mode={access_mode}")

            return success_response({
                "file_id": file_id,
                "expires_at": expires_at,
            })

        else:
            # File upload (default)
            file_size = body.get("file_size")
            validate_file_size(file_size)

            s3_key = f"files/{file_id}"

            # Create DynamoDB record
            create_file_record(
                table_name=TABLE_NAME,
                file_id=file_id,
                file_size=file_size,
                expires_at=expires_at,
                ip_hash=ip_hash,
                content_type="file",
                s3_key=s3_key,
                access_mode=access_mode,
                salt=salt,
                encrypted_key=encrypted_key,
            )

            # Generate presigned upload URL
            upload_url = generate_upload_url(
                bucket_name=BUCKET_NAME,
                s3_key=s3_key,
                expires_in=UPLOAD_URL_EXPIRY_SECONDS,
            )

            logger.info(f"File upload initialized: file_id={file_id}, size={file_size}, ttl={ttl}, access_mode={access_mode}")

            return success_response({
                "file_id": file_id,
                "upload_url": upload_url,
                "expires_at": expires_at,
            })

    except ValidationError as e:
        logger.warning(f"Validation error: {e}")
        return error_response(str(e), 400)

    except Exception as e:
        logger.exception("Unexpected error in upload_init")
        return error_response("Internal server error", 500)
