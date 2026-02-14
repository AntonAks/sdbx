"""Lambda function: Get statistics."""

import logging
import os
from typing import Any

from shared.dynamo import get_statistics
from shared.response import error_response, success_response
from shared.security import require_cloudfront_only

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Environment variables
TABLE_NAME = os.environ.get("TABLE_NAME")


@require_cloudfront_only
def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """
    Get global statistics.

    Security verification (CloudFront origin) is handled by decorator.
    No reCAPTCHA needed for read-only endpoint.

    Returns download count and other aggregate metrics.
    """
    try:
        # Get statistics from DynamoDB
        stats = get_statistics(TABLE_NAME)

        logger.info(f"Statistics retrieved: downloads={stats.get('downloads', 0)}")

        return success_response(stats)

    except Exception as e:
        logger.exception("Unexpected error getting statistics")
        return error_response("Internal server error", 500)
