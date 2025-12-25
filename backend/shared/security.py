"""Security helpers for request verification."""

import json
import logging
import os
from typing import Any, Optional

import requests

logger = logging.getLogger(__name__)

CLOUDFRONT_SECRET = os.environ.get('CLOUDFRONT_SECRET')
RECAPTCHA_SECRET_KEY = os.environ.get('RECAPTCHA_SECRET_KEY')
RECAPTCHA_VERIFY_URL = 'https://www.google.com/recaptcha/api/siteverify'
RECAPTCHA_MIN_SCORE = float(os.environ.get('RECAPTCHA_MIN_SCORE', '0.3'))  # Configurable minimum score


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


def verify_recaptcha(token: str, remote_ip: Optional[str] = None) -> tuple[bool, float, Optional[str]]:
    """
    Verify reCAPTCHA v3 token with Google.

    Args:
        token: reCAPTCHA token from frontend
        remote_ip: Optional IP address of the user

    Returns:
        Tuple of (is_valid, score, error_message)
        - is_valid: True if token is valid and score >= min_score
        - score: reCAPTCHA score (0.0 to 1.0)
        - error_message: Error description if validation fails
    """
    if not RECAPTCHA_SECRET_KEY:
        logger.warning("RECAPTCHA_SECRET_KEY not configured - skipping verification")
        return True, 1.0, None  # Allow in dev if not configured

    if not token:
        return False, 0.0, "reCAPTCHA token is required"

    try:
        # Verify token with Google
        payload = {
            'secret': RECAPTCHA_SECRET_KEY,
            'response': token,
        }
        if remote_ip:
            payload['remoteip'] = remote_ip

        response = requests.post(
            RECAPTCHA_VERIFY_URL,
            data=payload,
            timeout=5  # 5 second timeout
        )
        result = response.json()

        logger.info(json.dumps({
            'action': 'recaptcha_verification',
            'success': result.get('success', False),
            'score': result.get('score', 0.0),
            'hostname': result.get('hostname'),
        }))

        # Check if verification succeeded
        if not result.get('success', False):
            error_codes = result.get('error-codes', [])
            logger.warning(f"reCAPTCHA verification failed: {error_codes}")
            return False, 0.0, "reCAPTCHA verification failed"

        # Check score
        score = result.get('score', 0.0)
        if score < RECAPTCHA_MIN_SCORE:
            logger.warning(f"reCAPTCHA score too low: {score} < {RECAPTCHA_MIN_SCORE}")
            return False, score, "Bot activity detected"

        return True, score, None

    except requests.RequestException as e:
        logger.error(f"reCAPTCHA verification request failed: {e}")
        return False, 0.0, "Failed to verify reCAPTCHA"
    except Exception as e:
        logger.exception(f"Unexpected error during reCAPTCHA verification: {e}")
        return False, 0.0, "Internal error during verification"


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
