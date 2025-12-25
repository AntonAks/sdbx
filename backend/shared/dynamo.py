"""DynamoDB helper functions."""

import logging
import time
from datetime import datetime
from typing import Any, Optional

import boto3
from botocore.exceptions import ClientError

from .exceptions import FileAlreadyDownloadedError, FileExpiredError, FileNotFoundError

logger = logging.getLogger(__name__)

# Initialize DynamoDB client
dynamodb = boto3.resource("dynamodb")


def get_table(table_name: str):
    """Get DynamoDB table resource."""
    return dynamodb.Table(table_name)


def create_file_record(
    table_name: str,
    file_id: str,
    s3_key: str,
    file_size: int,
    expires_at: int,
    ip_hash: str,
) -> dict[str, Any]:
    """
    Create a new file record in DynamoDB.

    Args:
        table_name: DynamoDB table name
        file_id: Unique file ID (UUID)
        s3_key: S3 object key
        file_size: File size in bytes
        expires_at: Unix timestamp when file expires
        ip_hash: SHA256 hash of uploader IP

    Returns:
        Created file record
    """
    table = get_table(table_name)

    record = {
        "file_id": file_id,
        "s3_key": s3_key,
        "file_size": file_size,
        "created_at": datetime.utcnow().isoformat(),
        "expires_at": expires_at,
        "downloaded": False,
        "ip_hash": ip_hash,
        "report_count": 0,
    }

    table.put_item(Item=record)
    logger.info(f"Created file record: {file_id}")

    return record


def get_file_record(table_name: str, file_id: str) -> Optional[dict[str, Any]]:
    """
    Get file record from DynamoDB.

    Args:
        table_name: DynamoDB table name
        file_id: File ID

    Returns:
        File record or None if not found
    """
    table = get_table(table_name)

    try:
        response = table.get_item(Key={"file_id": file_id})
        return response.get("Item")
    except ClientError as e:
        logger.error(f"Error getting file record {file_id}: {e}")
        return None


def mark_downloaded(table_name: str, file_id: str) -> dict[str, Any]:
    """
    Atomically mark file as downloaded using conditional update.

    This prevents race conditions when multiple users try to download simultaneously.

    Args:
        table_name: DynamoDB table name
        file_id: File ID

    Returns:
        Updated file record

    Raises:
        FileAlreadyDownloadedError: If file was already downloaded
        FileExpiredError: If file has expired
        FileNotFoundError: If file doesn't exist
    """
    table = get_table(table_name)
    current_time = int(time.time())

    try:
        response = table.update_item(
            Key={"file_id": file_id},
            UpdateExpression="SET downloaded = :true, downloaded_at = :now",
            ConditionExpression="downloaded = :false AND expires_at > :current",
            ExpressionAttributeValues={
                ":true": True,
                ":false": False,
                ":now": datetime.utcnow().isoformat(),
                ":current": current_time,
            },
            ReturnValues="ALL_NEW",
        )
        logger.info(f"Marked file as downloaded: {file_id}")
        return response["Attributes"]

    except ClientError as e:
        error_code = e.response["Error"]["Code"]

        if error_code == "ConditionalCheckFailedException":
            # File was already downloaded or expired - check which
            record = get_file_record(table_name, file_id)

            if not record:
                raise FileNotFoundError("File not found")

            if record.get("downloaded"):
                raise FileAlreadyDownloadedError("File already downloaded")

            if record.get("expires_at", 0) <= current_time:
                raise FileExpiredError("File has expired")

            # Unknown condition failure
            raise

        logger.error(f"Error marking file as downloaded {file_id}: {e}")
        raise


def increment_report_count(table_name: str, file_id: str) -> int:
    """
    Increment abuse report count for a file.

    Args:
        table_name: DynamoDB table name
        file_id: File ID

    Returns:
        New report count
    """
    table = get_table(table_name)

    try:
        response = table.update_item(
            Key={"file_id": file_id},
            UpdateExpression="SET report_count = report_count + :inc",
            ExpressionAttributeValues={":inc": 1},
            ReturnValues="UPDATED_NEW",
        )
        new_count = response["Attributes"]["report_count"]
        logger.info(f"Incremented report count for {file_id}: {new_count}")
        return new_count

    except ClientError as e:
        logger.error(f"Error incrementing report count for {file_id}: {e}")
        raise


def delete_file_record(table_name: str, file_id: str) -> None:
    """
    Delete file record from DynamoDB.

    Args:
        table_name: DynamoDB table name
        file_id: File ID
    """
    table = get_table(table_name)

    try:
        table.delete_item(Key={"file_id": file_id})
        logger.info(f"Deleted file record: {file_id}")
    except ClientError as e:
        logger.error(f"Error deleting file record {file_id}: {e}")
        raise
