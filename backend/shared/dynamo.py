"""DynamoDB helper functions."""

import logging
import time
from datetime import datetime
from typing import Any, Optional

import boto3
from botocore.exceptions import ClientError

from .constants import DOWNLOAD_RESERVATION_TIMEOUT
from .exceptions import (
    FileAlreadyDownloadedError,
    FileExpiredError,
    FileNotFoundError,
    FileReservedError,
)

logger = logging.getLogger(__name__)

# Initialize DynamoDB client
dynamodb = boto3.resource("dynamodb")


def get_table(table_name: str):
    """Get DynamoDB table resource."""
    return dynamodb.Table(table_name)


def create_file_record(
    table_name: str,
    file_id: str,
    file_size: int,
    expires_at: int,
    ip_hash: str,
    content_type: str = "file",
    s3_key: Optional[str] = None,
    encrypted_text: Optional[str] = None,
) -> dict[str, Any]:
    """
    Create a new file or text secret record in DynamoDB.

    Args:
        table_name: DynamoDB table name
        file_id: Unique file/secret ID (UUID)
        file_size: File size in bytes (or encrypted text size)
        expires_at: Unix timestamp when secret expires
        ip_hash: SHA256 hash of uploader IP
        content_type: "file" or "text" (default: "file")
        s3_key: S3 object key (required for files)
        encrypted_text: Base64 encrypted text (required for text secrets)

    Returns:
        Created record
    """
    table = get_table(table_name)

    record = {
        "file_id": file_id,
        "content_type": content_type,
        "file_size": file_size,
        "created_at": datetime.utcnow().isoformat(),
        "expires_at": expires_at,
        "downloaded": False,
        "ip_hash": ip_hash,
        "report_count": 0,
    }

    # Add type-specific fields
    if content_type == "file":
        if not s3_key:
            raise ValueError("s3_key required for file content_type")
        record["s3_key"] = s3_key
    elif content_type == "text":
        if not encrypted_text:
            raise ValueError("encrypted_text required for text content_type")
        record["encrypted_text"] = encrypted_text

    table.put_item(Item=record)
    logger.info(f"Created {content_type} record: {file_id}")

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


def reserve_download(table_name: str, file_id: str) -> dict[str, Any]:
    """
    Atomically reserve file for download using conditional update.

    This prevents race conditions when multiple users try to download simultaneously.
    A reservation is valid for DOWNLOAD_RESERVATION_TIMEOUT seconds (10 minutes).
    If a previous reservation has expired, a new reservation can be made.

    Args:
        table_name: DynamoDB table name
        file_id: File ID

    Returns:
        File record with reservation timestamp

    Raises:
        FileReservedError: If file is currently reserved for download
        FileAlreadyDownloadedError: If file was already downloaded
        FileExpiredError: If file has expired
        FileNotFoundError: If file doesn't exist
    """
    table = get_table(table_name)
    current_time = int(time.time())
    reservation_cutoff = current_time - DOWNLOAD_RESERVATION_TIMEOUT

    try:
        response = table.update_item(
            Key={"file_id": file_id},
            UpdateExpression="SET reserved_at = :now",
            ConditionExpression=(
                "downloaded = :false AND expires_at > :current AND "
                "(attribute_not_exists(reserved_at) OR reserved_at < :cutoff)"
            ),
            ExpressionAttributeValues={
                ":false": False,
                ":now": current_time,
                ":current": current_time,
                ":cutoff": reservation_cutoff,
            },
            ReturnValues="ALL_NEW",
        )
        logger.info(f"Reserved file for download: {file_id}")
        return response["Attributes"]

    except ClientError as e:
        error_code = e.response["Error"]["Code"]

        if error_code == "ConditionalCheckFailedException":
            # Check why reservation failed
            record = get_file_record(table_name, file_id)

            if not record:
                raise FileNotFoundError("File not found")

            if record.get("downloaded"):
                raise FileAlreadyDownloadedError("File already downloaded")

            if record.get("expires_at", 0) <= current_time:
                raise FileExpiredError("File has expired")

            # File is currently reserved (reservation not expired yet)
            reserved_at = record.get("reserved_at", 0)
            if reserved_at >= reservation_cutoff:
                raise FileReservedError("File is currently being downloaded")

            # Unknown condition failure
            raise

        logger.error(f"Error reserving file for download {file_id}: {e}")
        raise


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


def confirm_download(table_name: str, file_id: str) -> dict[str, Any]:
    """
    Confirm successful download and mark file as downloaded.

    This should be called after the frontend successfully downloads and decrypts the file.
    It marks the file as downloaded and increments global statistics.

    Args:
        table_name: DynamoDB table name
        file_id: File ID

    Returns:
        Updated file record

    Raises:
        FileNotFoundError: If file doesn't exist
        FileAlreadyDownloadedError: If file was already confirmed as downloaded
    """
    table = get_table(table_name)
    current_time = int(time.time())

    try:
        response = table.update_item(
            Key={"file_id": file_id},
            UpdateExpression="SET downloaded = :true, downloaded_at = :now",
            ConditionExpression="downloaded = :false AND attribute_exists(reserved_at)",
            ExpressionAttributeValues={
                ":true": True,
                ":false": False,
                ":now": datetime.utcnow().isoformat(),
            },
            ReturnValues="ALL_NEW",
        )
        record = response["Attributes"]
        logger.info(f"Confirmed download for file: {file_id}")

        # Increment global download counter
        try:
            increment_download_counter(table_name, file_size=record.get("file_size", 0))
        except Exception as e:
            # Don't fail confirmation if counter increment fails
            logger.warning(f"Failed to increment download counter: {e}")

        return record

    except ClientError as e:
        error_code = e.response["Error"]["Code"]

        if error_code == "ConditionalCheckFailedException":
            # Check why confirmation failed
            record = get_file_record(table_name, file_id)

            if not record:
                raise FileNotFoundError("File not found")

            if record.get("downloaded"):
                raise FileAlreadyDownloadedError("File already confirmed as downloaded")

            # No reservation exists - shouldn't happen in normal flow
            logger.warning(f"Confirmation attempted without reservation: {file_id}")
            raise FileNotFoundError("No active download reservation found")

        logger.error(f"Error confirming download for {file_id}: {e}")
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


def increment_download_counter(table_name: str, file_size: int = 0) -> dict[str, Any]:
    """
    Atomically increment global download counter and total bytes.

    Uses a special statistics record with file_id="STATS" to track
    aggregate metrics without compromising user privacy.

    Args:
        table_name: DynamoDB table name
        file_size: Size of downloaded file in bytes

    Returns:
        Updated statistics (downloads, total_bytes)
    """
    table = get_table(table_name)

    try:
        response = table.update_item(
            Key={"file_id": "STATS"},
            UpdateExpression="ADD downloads :inc, total_bytes :size SET updated_at = :now",
            ExpressionAttributeValues={
                ":inc": 1,
                ":size": file_size,
                ":now": datetime.utcnow().isoformat(),
            },
            ReturnValues="ALL_NEW",
        )
        stats = response["Attributes"]
        logger.info(
            f"Incremented stats: downloads={stats.get('downloads', 0)}, "
            f"total_bytes={stats.get('total_bytes', 0)}"
        )
        return {
            "downloads": int(stats.get("downloads", 0)),
            "total_bytes": int(stats.get("total_bytes", 0)),
        }

    except ClientError as e:
        logger.error(f"Error incrementing download counter: {e}")
        raise


def get_statistics(table_name: str) -> dict[str, Any]:
    """
    Get global statistics.

    Args:
        table_name: DynamoDB table name

    Returns:
        Statistics dictionary with download count, total bytes, and other metrics
    """
    table = get_table(table_name)

    try:
        response = table.get_item(Key={"file_id": "STATS"})
        stats = response.get("Item", {})

        # Return statistics with defaults
        return {
            "downloads": int(stats.get("downloads", 0)),
            "total_bytes": int(stats.get("total_bytes", 0)),
            "updated_at": stats.get("updated_at", datetime.utcnow().isoformat()),
        }

    except ClientError as e:
        logger.error(f"Error getting statistics: {e}")
        # Return default stats if error
        return {
            "downloads": 0,
            "total_bytes": 0,
            "updated_at": datetime.utcnow().isoformat(),
        }
