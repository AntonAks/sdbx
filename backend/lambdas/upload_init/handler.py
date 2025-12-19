"""Lambda function: Initialize file upload."""

import hashlib
import json
import logging
import os
import time
import uuid
from typing import Any

from shared.dynamo import create_file_record
from shared.exceptions import ValidationError
from shared.s3 import generate_upload_url
from shared.security import verify_cloudfront_origin, verify_recaptcha, build_error_response
from shared.validation import validate_file_size, validate_ttl

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Environment variables
BUCKET_NAME = os.environ.get("BUCKET_NAME")
TABLE_NAME = os.environ.get("TABLE_NAME")
MAX_FILE_SIZE = int(os.environ.get("MAX_FILE_SIZE", 104857600))

# TTL mappings (hours to seconds)
TTL_TO_SECONDS = {
    "1h": 3600,
    "12h": 43200,
    "24h": 86400,
}


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """
    Initialize file upload.

    Expected request body:
    {
        "file_size": 1024,
        "ttl": "1h",
        "recaptcha_token": "token-from-frontend"
    }

    Returns:
    {
        "file_id": "uuid",
        "upload_url": "presigned-s3-url",
        "expires_at": 1234567890
    }
    """
    try:
        # Verify request comes from CloudFront
        if not verify_cloudfront_origin(event):
            return build_error_response(403, 'Direct API access not allowed')

        # Parse request body
        body = json.loads(event.get("body", "{}"))
        file_size = body.get("file_size")
        ttl = body.get("ttl")
        recaptcha_token = body.get("recaptcha_token")

        # Verify reCAPTCHA token
        source_ip = event.get("requestContext", {}).get("identity", {}).get("sourceIp")
        is_valid, score, error_msg = verify_recaptcha(recaptcha_token, source_ip)

        if not is_valid:
            logger.warning(f"reCAPTCHA verification failed: {error_msg} (score: {score})")
            return _error_response(403, error_msg or "Bot activity detected")

        logger.info(f"reCAPTCHA verification succeeded with score: {score}")

        # Validate input
        validate_file_size(file_size)
        validate_ttl(ttl)

        # Generate unique file ID
        file_id = str(uuid.uuid4())
        s3_key = f"files/{file_id}"

        # Calculate expiration timestamp
        ttl_seconds = TTL_TO_SECONDS[ttl]
        expires_at = int(time.time()) + ttl_seconds

        # Hash IP address (privacy)
        source_ip = event.get("requestContext", {}).get("identity", {}).get("sourceIp", "unknown")
        ip_hash = hashlib.sha256(source_ip.encode()).hexdigest()

        # Create DynamoDB record
        create_file_record(
            table_name=TABLE_NAME,
            file_id=file_id,
            s3_key=s3_key,
            file_size=file_size,
            expires_at=expires_at,
            ip_hash=ip_hash,
        )

        # Generate presigned upload URL (15 minutes)
        upload_url = generate_upload_url(
            bucket_name=BUCKET_NAME,
            s3_key=s3_key,
            expires_in=900,
        )

        return _success_response({
            "file_id": file_id,
            "upload_url": upload_url,
            "expires_at": expires_at,
        })

    except ValidationError as e:
        logger.warning(f"Validation error: {e}")
        return _error_response(400, str(e))

    except Exception as e:
        logger.exception("Unexpected error in upload_init")
        return _error_response(500, "Internal server error")


def _success_response(data: dict) -> dict[str, Any]:
    """Build successful API response."""
    return {
        "statusCode": 200,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
        },
        "body": json.dumps(data),
    }


def _error_response(status: int, message: str) -> dict[str, Any]:
    """Build error API response."""
    return {
        "statusCode": status,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
        },
        "body": json.dumps({"error": message}),
    }
