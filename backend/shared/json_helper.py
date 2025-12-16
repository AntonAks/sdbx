"""JSON utilities for handling DynamoDB Decimal types."""

import json
from decimal import Decimal


class DecimalEncoder(json.JSONEncoder):
    """JSON encoder that converts Decimal to int or float."""

    def default(self, obj):
        if isinstance(obj, Decimal):
            # Convert to int if it's a whole number, otherwise float
            if obj % 1 == 0:
                return int(obj)
            return float(obj)
        return super().default(obj)


def dumps(data: dict) -> str:
    """
    JSON dumps with Decimal support.

    Args:
        data: Dictionary to serialize

    Returns:
        JSON string
    """
    return json.dumps(data, cls=DecimalEncoder)
