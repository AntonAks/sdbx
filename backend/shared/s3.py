"""S3 helper functions."""

import logging
from typing import Optional

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

# Initialize S3 client
s3_client = boto3.client("s3")


def generate_upload_url(
    bucket_name: str,
    s3_key: str,
    expires_in: int = 900,
) -> str:
    """
    Generate presigned URL for uploading a file to S3.

    Args:
        bucket_name: S3 bucket name
        s3_key: S3 object key
        expires_in: URL expiration time in seconds (default 15 minutes)

    Returns:
        Presigned upload URL
    """
    try:
        url = s3_client.generate_presigned_url(
            "put_object",
            Params={
                "Bucket": bucket_name,
                "Key": s3_key,
            },
            ExpiresIn=expires_in,
        )
        logger.info(f"Generated upload URL for {s3_key}")
        return url

    except ClientError as e:
        logger.error(f"Error generating upload URL for {s3_key}: {e}")
        raise


def generate_download_url(
    bucket_name: str,
    s3_key: str,
    expires_in: int = 300,
) -> str:
    """
    Generate presigned URL for downloading a file from S3.

    Args:
        bucket_name: S3 bucket name
        s3_key: S3 object key
        expires_in: URL expiration time in seconds (default 5 minutes)

    Returns:
        Presigned download URL
    """
    try:
        url = s3_client.generate_presigned_url(
            "get_object",
            Params={
                "Bucket": bucket_name,
                "Key": s3_key,
            },
            ExpiresIn=expires_in,
        )
        logger.info(f"Generated download URL for {s3_key}")
        return url

    except ClientError as e:
        logger.error(f"Error generating download URL for {s3_key}: {e}")
        raise


def delete_file(bucket_name: str, s3_key: str) -> None:
    """
    Delete file from S3.

    Args:
        bucket_name: S3 bucket name
        s3_key: S3 object key
    """
    try:
        s3_client.delete_object(Bucket=bucket_name, Key=s3_key)
        logger.info(f"Deleted file from S3: {s3_key}")

    except ClientError as e:
        logger.error(f"Error deleting file {s3_key}: {e}")
        raise


def check_file_exists(bucket_name: str, s3_key: str) -> bool:
    """
    Check if file exists in S3.

    Args:
        bucket_name: S3 bucket name
        s3_key: S3 object key

    Returns:
        True if file exists, False otherwise
    """
    try:
        s3_client.head_object(Bucket=bucket_name, Key=s3_key)
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] == "404":
            return False
        logger.error(f"Error checking file existence {s3_key}: {e}")
        raise
