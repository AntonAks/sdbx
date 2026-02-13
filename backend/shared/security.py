"""Security helpers for request verification."""

import hashlib
import hmac
import json
import logging
import os
from functools import lru_cache, wraps
from typing import Any, Callable, Optional

import boto3
import requests

logger = logging.getLogger(__name__)

# Constants
RECAPTCHA_VERIFY_URL = 'https://www.google.com/recaptcha/api/siteverify'


def verify_cloudfront_origin(event: dict[str, Any]) -> bool:
    """
    Verify request comes from CloudFront (not direct API call).

    Args:
        event: Lambda event from API Gateway

    Returns:
        True if request is from CloudFront, False otherwise
    """
    # Read from env at runtime (not import time) for testability
    cloudfront_secret = os.environ.get('CLOUDFRONT_SECRET')

    if not cloudfront_secret:
        logger.warning("CLOUDFRONT_SECRET not configured - skipping origin check")
        return True  # Allow in dev if not configured

    # Get headers (normalize to lowercase)
    headers = event.get('headers', {})
    headers_lower = {k.lower(): v for k, v in headers.items()}

    # Check for custom header
    origin_verify = headers_lower.get('x-origin-verify', '')

    if origin_verify != cloudfront_secret:
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
    # Read from env at runtime (not import time) for testability
    recaptcha_secret_key = os.environ.get('RECAPTCHA_SECRET_KEY')
    recaptcha_min_score = float(os.environ.get('RECAPTCHA_MIN_SCORE', '0.3'))

    if not recaptcha_secret_key:
        logger.warning("RECAPTCHA_SECRET_KEY not configured - skipping verification")
        return True, 1.0, None  # Allow in dev if not configured

    if not token:
        return False, 0.0, "reCAPTCHA token is required"

    try:
        # Verify token with Google
        payload = {
            'secret': recaptcha_secret_key,
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
        if score < recaptcha_min_score:
            logger.warning(f"reCAPTCHA score too low: {score} < {recaptcha_min_score}")
            return False, score, "Bot activity detected"

        return True, score, None

    except requests.RequestException as e:
        logger.error(f"reCAPTCHA verification request failed: {e}")
        return False, 0.0, "Failed to verify reCAPTCHA"
    except Exception as e:
        logger.exception(f"Unexpected error during reCAPTCHA verification: {e}")
        return False, 0.0, "Internal error during verification"


def require_cloudfront_and_recaptcha(handler: Callable) -> Callable:
    """
    Decorator to verify CloudFront origin and reCAPTCHA for Lambda handlers.

    This decorator should be used on POST endpoints that modify data.
    It verifies:
    1. Request originates from CloudFront (blocks direct API access)
    2. Valid reCAPTCHA v3 token with sufficient score

    Usage:
        @require_cloudfront_and_recaptcha
        def handler(event, context):
            # Your handler code
            # Access verified reCAPTCHA score via event['_recaptcha_score']

    Args:
        handler: Lambda handler function to wrap

    Returns:
        Wrapped handler with security verification
    """
    @wraps(handler)
    def wrapper(event: dict[str, Any], context: Any) -> dict[str, Any]:
        # Import here to avoid circular dependency
        from shared.response import error_response

        # Verify CloudFront origin
        if not verify_cloudfront_origin(event):
            return error_response('Direct API access not allowed', 403)

        # Parse reCAPTCHA token from body
        try:
            body = json.loads(event.get("body", "{}"))
        except json.JSONDecodeError:
            return error_response('Invalid JSON in request body', 400)

        recaptcha_token = body.get("recaptcha_token")

        # Verify reCAPTCHA
        source_ip = event.get("requestContext", {}).get("identity", {}).get("sourceIp")
        is_valid, score, error_msg = verify_recaptcha(recaptcha_token, source_ip)

        if not is_valid:
            logger.warning(f"reCAPTCHA verification failed: {error_msg} (score: {score})")
            return error_response(error_msg or "Bot activity detected", 403)

        logger.info(f"Security verification passed (score: {score})")

        # Store verified info in event for handler use
        event['_security_verified'] = True
        event['_recaptcha_score'] = score

        return handler(event, context)

    return wrapper


def require_cloudfront_only(handler: Callable) -> Callable:
    """
    Decorator to verify CloudFront origin only (no reCAPTCHA).

    This decorator should be used on read-only GET endpoints that don't
    require bot protection but should still block direct API access.

    Usage:
        @require_cloudfront_only
        def handler(event, context):
            # Your handler code

    Args:
        handler: Lambda handler function to wrap

    Returns:
        Wrapped handler with CloudFront verification
    """
    @wraps(handler)
    def wrapper(event: dict[str, Any], context: Any) -> dict[str, Any]:
        # Import here to avoid circular dependency
        from shared.response import error_response

        # Verify CloudFront origin
        if not verify_cloudfront_origin(event):
            return error_response('Direct API access not allowed', 403)

        return handler(event, context)

    return wrapper


# Module-level cache for IP hash salt
_ip_hash_salt_cache = None


@lru_cache(maxsize=1)
def _get_ssm_parameter(param_name: str) -> str:
    """
    Retrieve a parameter from AWS Systems Manager Parameter Store.

    Uses LRU cache so only one API call per Lambda lifetime.

    Args:
        param_name: Full parameter name (e.g., /sdbx/dev/ip-hash-salt)

    Returns:
        Parameter value string
    """
    ssm_client = boto3.client('ssm')
    response = ssm_client.get_parameter(
        Name=param_name,
        WithDecryption=True
    )
    return response['Parameter']['Value']


def get_ip_hash_salt() -> str:
    """
    Get the IP hash salt from Parameter Store.

    Caches the salt in a module-level variable for performance.

    Returns:
        Salt string for HMAC hashing

    Raises:
        ValueError: If IP_HASH_SALT_PARAM env var is not set
    """
    global _ip_hash_salt_cache
    if _ip_hash_salt_cache is not None:
        return _ip_hash_salt_cache

    param_name = os.environ.get('IP_HASH_SALT_PARAM')
    if not param_name:
        raise ValueError("IP_HASH_SALT_PARAM environment variable is not set")

    _ip_hash_salt_cache = _get_ssm_parameter(param_name)
    return _ip_hash_salt_cache


def hash_ip_secure(ip: str) -> str:
    """
    Hash an IP address using HMAC-SHA256 with a secret salt.

    Args:
        ip: IP address string to hash

    Returns:
        64-character hex string (HMAC-SHA256 digest)
    """
    salt = get_ip_hash_salt()
    return hmac.new(salt.encode(), ip.encode(), hashlib.sha256).hexdigest()
