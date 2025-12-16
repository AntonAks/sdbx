"""Security helpers for request verification."""

import json
import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

CLOUDFRONT_SECRET = os.environ.get('CLOUDFRONT_SECRET')


def verify_cloudfront_origin(event: dict[str, Any]) -> bool:
    """
    Verify request comes from CloudFront (not direct API call).

    Args:
        event: Lambda event from API Gateway

    Returns:
        True if request is from CloudFront, False otherwise
    """
    if not CLOUDFRONT_SECRET:
        logger.warning("CLOUDFRONT_SECRET not configured - skipping origin check")
        return True  # Allow in dev if not configured

    # Get headers (normalize to lowercase)
    headers = event.get('headers', {})
    headers_lower = {k.lower(): v for k, v in headers.items()}

    # Check for custom header
    origin_verify = headers_lower.get('x-origin-verify', '')

    if origin_verify != CLOUDFRONT_SECRET:
        source_ip = event.get('requestContext', {}).get('identity', {}).get('sourceIp', 'unknown')
        logger.warning(f"Origin verification failed from IP: {source_ip}")
        return False

    return True


def build_error_response(status: int, message: str) -> dict[str, Any]:
    """Build standard error response."""
    return {
        'statusCode': status,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
        },
        'body': json.dumps({'error': message})
    }
