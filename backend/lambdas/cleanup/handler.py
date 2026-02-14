"""Lambda function: Cleanup expired files."""

import json
import logging
import os
import time
from typing import Any

import boto3

from shared.dynamo import delete_file_record, get_table
from shared.response import error_response, success_response
from shared.s3 import delete_file

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Environment variables
BUCKET_NAME = os.environ.get("BUCKET_NAME")
TABLE_NAME = os.environ.get("TABLE_NAME")


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """
    Cleanup expired and downloaded files and text secrets.

    For files: Deletes from S3 and DynamoDB
    For text: Deletes from DynamoDB only

    Runs on schedule (e.g., every hour via EventBridge).
    """
    try:
        deleted_count = 0
        error_count = 0
        current_time = int(time.time())

        # Scan for expired files with pagination
        # Note: In production, consider using a GSI on expires_at for efficiency
        table = get_table(TABLE_NAME)

        # Paginate through all items (DynamoDB scan returns max 1MB per request)
        last_evaluated_key = None

        while True:
            # Scan with pagination support
            if last_evaluated_key:
                response = table.scan(ExclusiveStartKey=last_evaluated_key)
            else:
                response = table.scan()

            for item in response.get("Items", []):
                file_id = item["file_id"]

                # Skip special records (statistics, etc.)
                if file_id == "STATS":
                    continue

                content_type = item.get("content_type", "file")
                expires_at = item.get("expires_at", 0)
                downloaded = item.get("downloaded", False)

                # Delete if expired or already downloaded
                should_delete = expires_at <= current_time or downloaded

                if should_delete:
                    try:
                        # Delete from S3 only if it's a file (not text)
                        if content_type == "file":
                            s3_key = item["s3_key"]
                            delete_file(BUCKET_NAME, s3_key)

                        # Delete from DynamoDB (both files and text)
                        delete_file_record(TABLE_NAME, file_id)

                        deleted_count += 1
                        logger.info(f"Cleaned up {content_type}: {file_id}")

                    except Exception as e:
                        error_count += 1
                        logger.error(f"Error cleaning up {file_id}: {e}")

            # Check if there are more items to scan
            last_evaluated_key = response.get("LastEvaluatedKey")
            if not last_evaluated_key:
                break  # No more items to scan

        logger.info(
            json.dumps({
                "action": "cleanup_completed",
                "deleted": deleted_count,
                "errors": error_count,
            })
        )

        return success_response({
            "deleted": deleted_count,
            "errors": error_count,
        })

    except Exception as e:
        logger.exception("Unexpected error in cleanup")
        return error_response("Internal server error", 500)
