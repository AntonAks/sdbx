"""Request parsing utilities for Lambda handlers."""

import json
import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)


def get_source_ip(event: dict[str, Any]) -> str:
    """
    Extract source IP address from API Gateway event.

    Args:
        event: Lambda event from API Gateway

    Returns:
        Source IP address or 'unknown' if not available
    """
    return event.get("requestContext", {}).get("identity", {}).get("sourceIp", "unknown")


def parse_json_body(event: dict[str, Any]) -> dict[str, Any]:
    """
    Safely parse JSON body from API Gateway event.

    Args:
        event: Lambda event from API Gateway

    Returns:
        Parsed body dict or empty dict if parsing fails

    Example:
        >>> event = {"body": '{"file_size": 1024}'}
        >>> parse_json_body(event)
        {'file_size': 1024}
    """
    body_str = event.get("body", "{}")

    if not body_str:
        return {}

    try:
        return json.loads(body_str)
    except json.JSONDecodeError as e:
        logger.warning(f"Failed to parse JSON body: {e}")
        return {}


def get_path_parameter(event: dict[str, Any], name: str) -> Optional[str]:
    """
    Extract a path parameter from API Gateway event.

    Args:
        event: Lambda event from API Gateway
        name: Parameter name to extract

    Returns:
        Parameter value or None if not found

    Example:
        >>> event = {"pathParameters": {"file_id": "123-456"}}
        >>> get_path_parameter(event, "file_id")
        '123-456'
    """
    return event.get("pathParameters", {}).get(name)


def get_query_parameter(event: dict[str, Any], name: str, default: Optional[str] = None) -> Optional[str]:
    """
    Extract a query string parameter from API Gateway event.

    Args:
        event: Lambda event from API Gateway
        name: Parameter name to extract
        default: Default value if parameter not found

    Returns:
        Parameter value or default

    Example:
        >>> event = {"queryStringParameters": {"limit": "10"}}
        >>> get_query_parameter(event, "limit")
        '10'
    """
    query_params = event.get("queryStringParameters")
    if not query_params:
        return default
    return query_params.get(name, default)
