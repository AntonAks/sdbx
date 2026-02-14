"""Input validation utilities."""

import re
from typing import Any

from .constants import (
    ALLOWED_ACCESS_MODES,
    ALLOWED_TTL_VALUES,
    MAX_CUSTOM_TTL_MINUTES,
    MAX_FILE_SIZE_BYTES,
    MAX_FILE_SIZE_MB,
    MIN_CUSTOM_TTL_MINUTES,
)
from .exceptions import ValidationError

# UUID pattern for file ID validation
UUID_PATTERN = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")

# PIN pattern: exactly 4 alphanumeric characters
PIN_PATTERN = re.compile(r"^[a-zA-Z0-9]{4}$")

# PIN file ID pattern: exactly 6 digits
PIN_FILE_ID_PATTERN = re.compile(r"^[0-9]{6}$")


def validate_file_id(file_id: str) -> None:
    """
    Validate file ID format (UUID v4).

    Args:
        file_id: File ID to validate

    Raises:
        ValidationError: If file ID is invalid
    """
    if not file_id:
        raise ValidationError("File ID is required")

    if not UUID_PATTERN.match(file_id.lower()):
        raise ValidationError("Invalid file ID format")


def validate_file_size(file_size: int) -> None:
    """
    Validate file size.

    Args:
        file_size: File size in bytes

    Raises:
        ValidationError: If file size is invalid
    """
    if not isinstance(file_size, int):
        raise ValidationError("File size must be an integer")

    if file_size <= 0:
        raise ValidationError("File size must be positive")

    if file_size > MAX_FILE_SIZE_BYTES:
        raise ValidationError(f"File size exceeds maximum limit ({MAX_FILE_SIZE_MB} MB)")


def validate_ttl(ttl: Any) -> None:
    """
    Validate TTL value.

    Accepts either:
    - Preset strings: "1h", "12h", "24h"
    - Numeric minutes: 5 to 10080 (5 min to 7 days)

    Args:
        ttl: Time to live value

    Raises:
        ValidationError: If TTL is invalid
    """
    # Accept preset strings
    if isinstance(ttl, str) and ttl in ALLOWED_TTL_VALUES:
        return

    # Accept numeric minutes
    if isinstance(ttl, (int, float)):
        minutes = int(ttl)
        if minutes < MIN_CUSTOM_TTL_MINUTES:
            raise ValidationError(
                f"Custom TTL must be at least {MIN_CUSTOM_TTL_MINUTES} minutes"
            )
        if minutes > MAX_CUSTOM_TTL_MINUTES:
            raise ValidationError(
                f"Custom TTL cannot exceed {MAX_CUSTOM_TTL_MINUTES} minutes (7 days)"
            )
        return

    # Invalid format
    raise ValidationError(
        f"TTL must be one of {ALLOWED_TTL_VALUES} or a number of minutes ({MIN_CUSTOM_TTL_MINUTES}-{MAX_CUSTOM_TTL_MINUTES})"
    )


def validate_access_mode(access_mode: Any) -> None:
    """
    Validate access mode.

    Args:
        access_mode: Access mode value ("one_time" or "multi")

    Raises:
        ValidationError: If access mode is invalid
    """
    if access_mode not in ALLOWED_ACCESS_MODES:
        raise ValidationError(f"Access mode must be one of {ALLOWED_ACCESS_MODES}")


def validate_salt(salt: Any) -> None:
    """
    Validate salt for password-protected vault.

    Args:
        salt: Base64-encoded salt string

    Raises:
        ValidationError: If salt is invalid
    """
    if not isinstance(salt, str):
        raise ValidationError("Salt must be a string")

    if not salt:
        raise ValidationError("Salt is required for vault access")

    # Base64 encoded 16-byte salt should be ~24 chars, allow some margin
    if len(salt) > 50:
        raise ValidationError("Invalid salt format")


def validate_encrypted_key(encrypted_key: Any) -> None:
    """
    Validate encrypted key for password-protected vault.

    Args:
        encrypted_key: Base64-encoded encrypted key string

    Raises:
        ValidationError: If encrypted key is invalid
    """
    if not isinstance(encrypted_key, str):
        raise ValidationError("Encrypted key must be a string")

    if not encrypted_key:
        raise ValidationError("Encrypted key is required for vault access")

    # Base64 encoded IV (12 bytes) + encrypted key (32 bytes) + auth tag (16 bytes)
    # Should be ~80 chars, allow margin for variations
    if len(encrypted_key) > 200:
        raise ValidationError("Invalid encrypted key format")


def validate_pin(pin: Any) -> None:
    """Validate PIN format (exactly 4 alphanumeric characters)."""
    if not pin:
        raise ValidationError("PIN is required")
    if not isinstance(pin, str):
        raise ValidationError("PIN must be a string")
    if len(pin) != 4:
        raise ValidationError("PIN must be exactly 4 characters")
    if not PIN_PATTERN.match(pin):
        raise ValidationError("PIN must contain only letters and numbers")


def validate_pin_file_id(file_id: Any) -> None:
    """Validate 6-digit numeric file ID for PIN-based sharing."""
    if not file_id:
        raise ValidationError("File ID is required")
    if not isinstance(file_id, str):
        raise ValidationError("File ID must be a string")
    if not PIN_FILE_ID_PATTERN.match(file_id):
        raise ValidationError("File ID must be exactly 6 digits")
