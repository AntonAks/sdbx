"""DynamoDB helper functions."""

import logging
import time
from datetime import datetime
from typing import Any, Optional

import boto3
from botocore.exceptions import ClientError

from .constants import (
    ACCESS_MODE_MULTI,
    ACCESS_MODE_ONE_TIME,
    ACCESS_MODE_PIN,
    DOWNLOAD_RESERVATION_TIMEOUT,
    PIN_LOCKOUT_SECONDS,
    PIN_MAX_ATTEMPTS,
    PIN_SESSION_TIMEOUT_SECONDS,
)
from .exceptions import (
    FileAlreadyDownloadedError,
    FileExpiredError,
    FileLockedException,
    FileNotFoundError,
    FileReservedError,
    SessionExpiredError,
    ValidationError,
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
    access_mode: str = ACCESS_MODE_ONE_TIME,
    salt: Optional[str] = None,
    encrypted_key: Optional[str] = None,
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
        access_mode: "one_time" (default) or "multi" for vault
        salt: Base64 salt for PBKDF2 (required for multi access)
        encrypted_key: Base64 encrypted AES key (required for multi access)

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
        "access_mode": access_mode,
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

    # Add vault-specific fields for multi-access mode
    if access_mode == ACCESS_MODE_MULTI:
        if not salt:
            raise ValueError("salt required for multi access mode")
        if not encrypted_key:
            raise ValueError("encrypted_key required for multi access mode")
        record["salt"] = salt
        record["encrypted_key"] = encrypted_key
        record["download_count"] = 0

    table.put_item(Item=record)
    logger.info(f"Created {content_type} record ({access_mode}): {file_id}")

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


def increment_vault_download(table_name: str, file_id: str) -> dict[str, Any]:
    """
    Increment download count for a vault (multi-access) record.

    Unlike one-time downloads, this does NOT mark the file as downloaded,
    allowing unlimited downloads until the TTL expires.

    Args:
        table_name: DynamoDB table name
        file_id: File ID

    Returns:
        Updated file record with new download_count

    Raises:
        FileExpiredError: If file has expired
        FileNotFoundError: If file doesn't exist
    """
    table = get_table(table_name)
    current_time = int(time.time())

    try:
        response = table.update_item(
            Key={"file_id": file_id},
            UpdateExpression="SET download_count = if_not_exists(download_count, :zero) + :inc, last_downloaded_at = :now",
            ConditionExpression="expires_at > :current AND access_mode = :multi",
            ExpressionAttributeValues={
                ":inc": 1,
                ":zero": 0,
                ":now": datetime.utcnow().isoformat(),
                ":current": current_time,
                ":multi": ACCESS_MODE_MULTI,
            },
            ReturnValues="ALL_NEW",
        )
        record = response["Attributes"]
        logger.info(f"Vault download #{record.get('download_count', 1)} for: {file_id}")

        # Increment global download counter
        try:
            increment_download_counter(table_name, file_size=record.get("file_size", 0))
        except Exception as e:
            # Don't fail if counter increment fails
            logger.warning(f"Failed to increment download counter: {e}")

        return record

    except ClientError as e:
        error_code = e.response["Error"]["Code"]

        if error_code == "ConditionalCheckFailedException":
            # Check why it failed
            record = get_file_record(table_name, file_id)

            if not record:
                raise FileNotFoundError("File not found")

            if record.get("expires_at", 0) <= current_time:
                raise FileExpiredError("File has expired")

            if record.get("access_mode") != ACCESS_MODE_MULTI:
                # Should not happen - wrong function called
                logger.error(f"increment_vault_download called for non-vault record: {file_id}")
                raise ValueError("This is not a vault record")

            raise

        logger.error(f"Error incrementing vault download for {file_id}: {e}")
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
            UpdateExpression="SET report_count = if_not_exists(report_count, :zero) + :inc",
            ExpressionAttributeValues={":inc": 1, ":zero": 0},
            ReturnValues="UPDATED_NEW",
        )
        new_count = response["Attributes"]["report_count"]
        logger.info(f"Incremented report count for {file_id}: {new_count}")
        return int(new_count)

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


def create_pin_file_record(
    table_name: str,
    file_id: str,
    file_size: int,
    expires_at: int,
    ip_hash: str,
    pin_hash: str,
    salt: str,
    content_type: str = "file",
    s3_key: Optional[str] = None,
    encrypted_text: Optional[str] = None,
    file_name: Optional[str] = None,
    one_time: bool = True,
) -> dict[str, Any]:
    """
    Create a DynamoDB record for PIN-based sharing.

    Uses conditional put to prevent file_id collisions.

    Args:
        table_name: DynamoDB table name
        file_id: Short file ID (6 chars)
        file_size: File size in bytes (or encrypted text size)
        expires_at: Unix timestamp when secret expires
        ip_hash: SHA256 hash of uploader IP
        pin_hash: PBKDF2-hashed PIN
        salt: Base64-encoded salt for PIN hashing
        content_type: "file" or "text" (default: "file")
        s3_key: S3 object key (required for files)
        encrypted_text: Base64 encrypted text (required for text secrets)
        one_time: If True, delete after first download (default: True)

    Returns:
        Created record

    Raises:
        ValueError: If required fields are missing or file_id already exists
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
        "access_mode": ACCESS_MODE_PIN,
        "pin_hash": pin_hash,
        "salt": salt,
        "attempts_left": PIN_MAX_ATTEMPTS,
        "one_time": one_time,
    }

    if file_name:
        record["file_name"] = file_name

    if content_type == "file":
        if not s3_key:
            raise ValueError("s3_key required for file content_type")
        record["s3_key"] = s3_key
    elif content_type == "text":
        if not encrypted_text:
            raise ValueError("encrypted_text required for text content_type")
        record["encrypted_text"] = encrypted_text

    try:
        table.put_item(Item=record, ConditionExpression="attribute_not_exists(file_id)")
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            raise ValueError(f"File ID {file_id} already exists")
        raise

    logger.info(f"Created PIN {content_type} record: {file_id}")
    return record


def initiate_pin_session(table_name: str, file_id: str) -> dict[str, Any]:
    """
    Create a 60-second PIN entry session.

    Checks file exists, not expired, not downloaded, not locked.
    Resets attempts if lockout has expired.

    Args:
        table_name: DynamoDB table name
        file_id: File ID

    Returns:
        Session info with session_expires and attempts_left

    Raises:
        FileNotFoundError: If file doesn't exist or is not PIN mode
        FileAlreadyDownloadedError: If file was already downloaded
        FileExpiredError: If file has expired
        FileLockedException: If file is locked due to failed attempts
    """
    table = get_table(table_name)
    current_time = int(time.time())
    session_expires = current_time + PIN_SESSION_TIMEOUT_SECONDS

    record = get_file_record(table_name, file_id)
    if not record:
        raise FileNotFoundError("File not found")
    if record.get("downloaded"):
        raise FileAlreadyDownloadedError("File has already been downloaded")
    if record.get("expires_at", 0) <= current_time:
        raise FileExpiredError("File has expired")
    if record.get("access_mode") != ACCESS_MODE_PIN:
        raise FileNotFoundError("File not found")

    locked_until = record.get("locked_until")
    if locked_until is not None and int(locked_until) > current_time:
        remaining_seconds = int(locked_until) - current_time
        remaining_hours = remaining_seconds // 3600 + (1 if remaining_seconds % 3600 else 0)
        raise FileLockedException(f"File is locked. Try again in {remaining_hours} hours")

    attempts_left = int(record.get("attempts_left", PIN_MAX_ATTEMPTS))

    update_expr = "SET session_started = :started, session_expires = :expires"
    expr_values: dict[str, Any] = {":started": current_time, ":expires": session_expires}

    # Reset attempts if lockout has expired
    if locked_until is not None and int(locked_until) <= current_time:
        update_expr += ", attempts_left = :max_attempts REMOVE locked_until"
        expr_values[":max_attempts"] = PIN_MAX_ATTEMPTS
        attempts_left = PIN_MAX_ATTEMPTS

    try:
        table.update_item(
            Key={"file_id": file_id},
            UpdateExpression=update_expr,
            ExpressionAttributeValues=expr_values,
        )
    except ClientError as e:
        logger.error(f"Error creating PIN session for {file_id}: {e}")
        raise

    logger.info(f"PIN session created for: {file_id}, expires: {session_expires}")
    return {"session_expires": session_expires, "attempts_left": attempts_left}


def verify_pin_and_download(table_name: str, file_id: str, pin: str) -> dict[str, Any]:
    """
    Verify PIN and reserve file for download.

    Decrements attempts on failure, locks after 3 failures, reserves file on success.

    Args:
        table_name: DynamoDB table name
        file_id: File ID
        pin: User-provided PIN to verify

    Returns:
        File record with reservation on success

    Raises:
        FileNotFoundError: If file doesn't exist or is not PIN mode
        FileAlreadyDownloadedError: If file was already downloaded
        FileExpiredError: If file has expired
        SessionExpiredError: If PIN session has expired
        FileLockedException: If file is locked due to failed attempts
        ValidationError: If PIN is incorrect (with remaining attempts)
    """
    from .pin_utils import verify_pin_hash

    table = get_table(table_name)
    current_time = int(time.time())

    record = get_file_record(table_name, file_id)
    if not record:
        raise FileNotFoundError("File not found")
    if record.get("access_mode") != ACCESS_MODE_PIN:
        raise FileNotFoundError("File not found")
    if record.get("downloaded"):
        raise FileAlreadyDownloadedError("File has already been downloaded")
    if record.get("expires_at", 0) <= current_time:
        raise FileExpiredError("File has expired")

    session_expires = record.get("session_expires")
    if not session_expires or int(session_expires) <= current_time:
        raise SessionExpiredError("Session expired. Please enter file ID again")

    locked_until = record.get("locked_until")
    if locked_until is not None and int(locked_until) > current_time:
        remaining_seconds = int(locked_until) - current_time
        remaining_hours = remaining_seconds // 3600 + (1 if remaining_seconds % 3600 else 0)
        raise FileLockedException(f"File is locked. Try again in {remaining_hours} hours")

    attempts_left = int(record.get("attempts_left", 0))
    if attempts_left <= 0:
        raise FileLockedException("File is locked for 12 hours")

    if not verify_pin_hash(pin, record["salt"], record["pin_hash"]):
        new_attempts = attempts_left - 1
        update_expr = "SET attempts_left = :attempts"
        expr_values: dict[str, Any] = {":attempts": new_attempts}

        if new_attempts <= 0:
            expr_values[":locked"] = current_time + PIN_LOCKOUT_SECONDS
            update_expr += ", locked_until = :locked"

        try:
            table.update_item(
                Key={"file_id": file_id},
                UpdateExpression=update_expr,
                ExpressionAttributeValues=expr_values,
            )
        except ClientError as e:
            logger.error(f"Error updating PIN attempts for {file_id}: {e}")

        if new_attempts <= 0:
            raise FileLockedException("Incorrect PIN. File locked for 12 hours")
        raise ValidationError(f"Incorrect PIN. {new_attempts} attempts left")

    # PIN correct - reserve file for download
    is_one_time = record.get("one_time", True)
    try:
        if is_one_time:
            # One-time mode: atomically mark as downloaded
            response = table.update_item(
                Key={"file_id": file_id},
                UpdateExpression="SET reserved_at = :now, downloaded = :true, downloaded_at = :now_iso",
                ConditionExpression="downloaded = :false AND expires_at > :current",
                ExpressionAttributeValues={
                    ":false": False,
                    ":true": True,
                    ":now": current_time,
                    ":now_iso": datetime.utcnow().isoformat(),
                    ":current": current_time,
                },
                ReturnValues="ALL_NEW",
            )
        else:
            # Multi mode: allow repeated downloads until expiry
            response = table.update_item(
                Key={"file_id": file_id},
                UpdateExpression="SET reserved_at = :now ADD download_count :inc",
                ConditionExpression="expires_at > :current",
                ExpressionAttributeValues={
                    ":now": current_time,
                    ":current": current_time,
                    ":inc": 1,
                },
                ReturnValues="ALL_NEW",
            )
        logger.info(f"PIN verified, file reserved: {file_id} (one_time={is_one_time})")
        return response["Attributes"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            if is_one_time:
                raise FileAlreadyDownloadedError("File has already been downloaded")
            raise FileExpiredError("File has expired")
        raise
