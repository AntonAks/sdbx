"""Application constants and configuration."""

from typing import Final

# File size limits
MAX_FILE_SIZE_BYTES: Final[int] = 524288000  # 500 MB
MAX_FILE_SIZE_MB: Final[int] = 500

# TTL mappings
TTL_TO_SECONDS: Final[dict[str, int]] = {
    "1h": 3600,
    "12h": 43200,
    "24h": 86400,
}

ALLOWED_TTL_VALUES: Final[tuple[str, ...]] = ("1h", "12h", "24h")

# Presigned URL expiry times (in seconds)
UPLOAD_URL_EXPIRY_SECONDS: Final[int] = 900  # 15 minutes
DOWNLOAD_URL_EXPIRY_SECONDS: Final[int] = 300  # 5 minutes

# Download reservation timeout (in seconds)
DOWNLOAD_RESERVATION_TIMEOUT: Final[int] = 600  # 10 minutes

# Abuse reporting
AUTO_DELETE_THRESHOLD: Final[int] = 3  # Number of reports before auto-delete

# HTTP Status Codes (for documentation and consistency)
HTTP_OK: Final[int] = 200
HTTP_BAD_REQUEST: Final[int] = 400
HTTP_FORBIDDEN: Final[int] = 403
HTTP_NOT_FOUND: Final[int] = 404
HTTP_GONE: Final[int] = 410
HTTP_PAYLOAD_TOO_LARGE: Final[int] = 413
HTTP_INTERNAL_ERROR: Final[int] = 500
