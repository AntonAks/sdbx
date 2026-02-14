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

# Custom TTL limits (in minutes)
MIN_CUSTOM_TTL_MINUTES: Final[int] = 5        # 5 minutes
MAX_CUSTOM_TTL_MINUTES: Final[int] = 10080    # 7 days (7 * 24 * 60)

# Presigned URL expiry times (in seconds)
UPLOAD_URL_EXPIRY_SECONDS: Final[int] = 900  # 15 minutes
DOWNLOAD_URL_EXPIRY_SECONDS: Final[int] = 300  # 5 minutes

# Download reservation timeout (in seconds)
DOWNLOAD_RESERVATION_TIMEOUT: Final[int] = 600  # 10 minutes

# Abuse reporting
AUTO_DELETE_THRESHOLD: Final[int] = 3  # Number of reports before auto-delete

# Access modes
ACCESS_MODE_ONE_TIME: Final[str] = "one_time"
ACCESS_MODE_MULTI: Final[str] = "multi"
ACCESS_MODE_PIN: Final[str] = "pin"
ALLOWED_ACCESS_MODES: Final[tuple[str, ...]] = (ACCESS_MODE_ONE_TIME, ACCESS_MODE_MULTI, ACCESS_MODE_PIN)

# PIN-based sharing
PIN_LENGTH: Final[int] = 4
PIN_FILE_ID_LENGTH: Final[int] = 6
PIN_MAX_ATTEMPTS: Final[int] = 3
PIN_LOCKOUT_SECONDS: Final[int] = 43200  # 12 hours
PIN_SESSION_TIMEOUT_SECONDS: Final[int] = 60
PIN_PBKDF2_ITERATIONS: Final[int] = 100000
PIN_SALT_BYTES: Final[int] = 32

# HTTP Status Codes (for documentation and consistency)
HTTP_OK: Final[int] = 200
HTTP_BAD_REQUEST: Final[int] = 400
HTTP_FORBIDDEN: Final[int] = 403
HTTP_NOT_FOUND: Final[int] = 404
HTTP_GONE: Final[int] = 410
HTTP_PAYLOAD_TOO_LARGE: Final[int] = 413
HTTP_INTERNAL_ERROR: Final[int] = 500
