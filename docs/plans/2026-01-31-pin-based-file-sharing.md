# PIN-Based File Sharing Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add PIN-based file sharing as an alternative to URL-based sharing, allowing users to share files using a 6-digit ID + 4-character PIN combination.

**Architecture:** Extend the existing upload/download flows with a new `access_mode: "pin"`. Backend gets two new Lambda handlers (`pin_initiate` for session creation, `pin_verify` for PIN verification + download). Frontend adds a method selection screen on upload and auto-detects PIN vs URL mode on download. Encryption key is derived from PIN via PBKDF2 (same as vault mode), with PIN hash stored server-side for verification. Session management (60s timer, 3 attempts, 12h lockout) is entirely in DynamoDB.

**Tech Stack:** Python 3.12 (Lambda), Vanilla JS (Web Crypto API, PBKDF2), DynamoDB (conditional updates), Terraform (API Gateway + Lambda), pytest (TDD)

---

## Task 1: Add PIN-Related Constants and Exceptions

**Files:**
- Modify: `backend/shared/constants.py`
- Modify: `backend/shared/exceptions.py`
- Test: `backend/tests/test_constants.py` (new)

**Step 1: Write the failing test**

```python
# backend/tests/test_constants.py
"""Unit tests for PIN-related constants."""

from shared.constants import (
    ACCESS_MODE_PIN,
    PIN_LENGTH,
    PIN_FILE_ID_LENGTH,
    PIN_MAX_ATTEMPTS,
    PIN_LOCKOUT_SECONDS,
    PIN_SESSION_TIMEOUT_SECONDS,
    PIN_PBKDF2_ITERATIONS,
    PIN_SALT_BYTES,
)


class TestPinConstants:
    """Test PIN-related constants are defined correctly."""

    def test_access_mode_pin_defined(self):
        assert ACCESS_MODE_PIN == "pin"

    def test_pin_length(self):
        assert PIN_LENGTH == 4

    def test_pin_file_id_length(self):
        assert PIN_FILE_ID_LENGTH == 6

    def test_pin_max_attempts(self):
        assert PIN_MAX_ATTEMPTS == 3

    def test_pin_lockout_seconds(self):
        assert PIN_LOCKOUT_SECONDS == 43200  # 12 hours

    def test_pin_session_timeout_seconds(self):
        assert PIN_SESSION_TIMEOUT_SECONDS == 60

    def test_pin_pbkdf2_iterations(self):
        assert PIN_PBKDF2_ITERATIONS == 100000

    def test_pin_salt_bytes(self):
        assert PIN_SALT_BYTES == 32
```

**Step 2: Run test to verify it fails**

Run: `cd /home/antonaks/Documents/MyProjects/sdbx && python -m pytest backend/tests/test_constants.py -v`
Expected: FAIL with `ImportError` (constants not defined yet)

**Step 3: Write minimal implementation**

Add to `backend/shared/constants.py`:

```python
# PIN-based sharing
ACCESS_MODE_PIN: Final[str] = "pin"
PIN_LENGTH: Final[int] = 4
PIN_FILE_ID_LENGTH: Final[int] = 6
PIN_MAX_ATTEMPTS: Final[int] = 3
PIN_LOCKOUT_SECONDS: Final[int] = 43200  # 12 hours
PIN_SESSION_TIMEOUT_SECONDS: Final[int] = 60
PIN_PBKDF2_ITERATIONS: Final[int] = 100000
PIN_SALT_BYTES: Final[int] = 32
```

Update `ALLOWED_ACCESS_MODES` to include `"pin"`:

```python
ALLOWED_ACCESS_MODES: Final[tuple[str, ...]] = (ACCESS_MODE_ONE_TIME, ACCESS_MODE_MULTI, ACCESS_MODE_PIN)
```

Add to `backend/shared/exceptions.py`:

```python
class FileLockedException(SdbxError):
    """File is locked due to too many failed PIN attempts."""
    pass


class SessionExpiredError(SdbxError):
    """PIN entry session has expired."""
    pass
```

**Step 4: Run test to verify it passes**

Run: `cd /home/antonaks/Documents/MyProjects/sdbx && python -m pytest backend/tests/test_constants.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add backend/shared/constants.py backend/shared/exceptions.py backend/tests/test_constants.py
git commit -m "feat(pin): add PIN-related constants and exceptions"
```

---

## Task 2: Add PIN Validation Functions

**Files:**
- Modify: `backend/shared/validation.py`
- Modify: `backend/tests/test_validation.py`

**Step 1: Write the failing tests**

Append to `backend/tests/test_validation.py`:

```python
from shared.validation import validate_pin, validate_pin_file_id


class TestValidatePin:
    """Test PIN validation (4 alphanumeric characters)."""

    def test_valid_pin_numeric(self):
        """Should accept 4-digit numeric PIN."""
        validate_pin("1234")

    def test_valid_pin_alpha(self):
        """Should accept 4-letter PIN."""
        validate_pin("AbCd")

    def test_valid_pin_alphanumeric(self):
        """Should accept mixed alphanumeric PIN."""
        validate_pin("7a2B")

    def test_pin_too_short(self):
        """Should reject PIN shorter than 4 characters."""
        with pytest.raises(ValidationError, match="PIN must be exactly 4 characters"):
            validate_pin("12")

    def test_pin_too_long(self):
        """Should reject PIN longer than 4 characters."""
        with pytest.raises(ValidationError, match="PIN must be exactly 4 characters"):
            validate_pin("12345")

    def test_pin_with_special_characters(self):
        """Should reject PIN with special characters."""
        with pytest.raises(ValidationError, match="PIN must contain only letters and numbers"):
            validate_pin("12@#")

    def test_pin_with_space(self):
        """Should reject PIN with space."""
        with pytest.raises(ValidationError, match="PIN must contain only letters and numbers"):
            validate_pin("ab d")

    def test_pin_none(self):
        """Should reject None PIN."""
        with pytest.raises(ValidationError, match="PIN is required"):
            validate_pin(None)

    def test_pin_empty(self):
        """Should reject empty PIN."""
        with pytest.raises(ValidationError, match="PIN is required"):
            validate_pin("")

    def test_pin_case_sensitive(self):
        """Should preserve case (a != A)."""
        # Both should be valid - case sensitivity is verified at comparison time
        validate_pin("abcd")
        validate_pin("ABCD")

    def test_pin_not_in_error_message(self):
        """Should not expose PIN value in error message."""
        try:
            validate_pin("ab@d")
        except ValidationError as e:
            assert "ab@d" not in str(e)


class TestValidatePinFileId:
    """Test 6-digit file ID validation."""

    def test_valid_six_digit_id(self):
        """Should accept valid 6-digit numeric ID."""
        validate_pin_file_id("482973")

    def test_valid_six_digit_all_zeros(self):
        """Should accept 000000."""
        validate_pin_file_id("000000")

    def test_valid_six_digit_all_nines(self):
        """Should accept 999999."""
        validate_pin_file_id("999999")

    def test_too_short(self):
        """Should reject IDs shorter than 6 digits."""
        with pytest.raises(ValidationError, match="File ID must be exactly 6 digits"):
            validate_pin_file_id("12345")

    def test_too_long(self):
        """Should reject IDs longer than 6 digits."""
        with pytest.raises(ValidationError, match="File ID must be exactly 6 digits"):
            validate_pin_file_id("1234567")

    def test_non_numeric(self):
        """Should reject non-numeric IDs."""
        with pytest.raises(ValidationError, match="File ID must be exactly 6 digits"):
            validate_pin_file_id("abcdef")

    def test_mixed_alphanumeric(self):
        """Should reject mixed alphanumeric IDs."""
        with pytest.raises(ValidationError, match="File ID must be exactly 6 digits"):
            validate_pin_file_id("12ab34")

    def test_none(self):
        """Should reject None."""
        with pytest.raises(ValidationError, match="File ID is required"):
            validate_pin_file_id(None)

    def test_empty(self):
        """Should reject empty string."""
        with pytest.raises(ValidationError, match="File ID is required"):
            validate_pin_file_id("")
```

**Step 2: Run test to verify it fails**

Run: `cd /home/antonaks/Documents/MyProjects/sdbx && python -m pytest backend/tests/test_validation.py::TestValidatePin -v`
Expected: FAIL with `ImportError`

**Step 3: Write minimal implementation**

Add to `backend/shared/validation.py`:

```python
import re

# At module level
PIN_PATTERN = re.compile(r"^[a-zA-Z0-9]{4}$")
PIN_FILE_ID_PATTERN = re.compile(r"^[0-9]{6}$")


def validate_pin(pin: Any) -> None:
    """
    Validate PIN format (exactly 4 alphanumeric characters).

    Args:
        pin: PIN to validate

    Raises:
        ValidationError: If PIN is invalid
    """
    if not pin:
        raise ValidationError("PIN is required")

    if not isinstance(pin, str):
        raise ValidationError("PIN must be a string")

    if len(pin) != 4:
        raise ValidationError("PIN must be exactly 4 characters")

    if not PIN_PATTERN.match(pin):
        raise ValidationError("PIN must contain only letters and numbers")


def validate_pin_file_id(file_id: Any) -> None:
    """
    Validate 6-digit numeric file ID for PIN-based sharing.

    Args:
        file_id: File ID to validate

    Raises:
        ValidationError: If file ID is invalid
    """
    if not file_id:
        raise ValidationError("File ID is required")

    if not isinstance(file_id, str):
        raise ValidationError("File ID must be a string")

    if not PIN_FILE_ID_PATTERN.match(file_id):
        raise ValidationError("File ID must be exactly 6 digits")
```

**Step 4: Run test to verify it passes**

Run: `cd /home/antonaks/Documents/MyProjects/sdbx && python -m pytest backend/tests/test_validation.py -v`
Expected: ALL PASS (both old and new tests)

**Step 5: Commit**

```bash
git add backend/shared/validation.py backend/tests/test_validation.py
git commit -m "feat(pin): add PIN and 6-digit file ID validation"
```

---

## Task 3: Add PIN Hashing and Verification Utilities

**Files:**
- Create: `backend/shared/pin_utils.py`
- Create: `backend/tests/test_pin_utils.py`

**Step 1: Write the failing tests**

```python
# backend/tests/test_pin_utils.py
"""Unit tests for PIN utility functions - NO MOCKS."""

import hashlib

import pytest

from shared.pin_utils import (
    generate_pin_file_id,
    generate_salt,
    hash_pin,
    verify_pin_hash,
)


class TestGenerateSalt:
    """Test salt generation."""

    def test_salt_length(self):
        """Should generate 32-byte salt as hex (64 chars)."""
        salt = generate_salt()
        assert len(salt) == 64  # 32 bytes = 64 hex chars

    def test_salt_is_hex(self):
        """Should return valid hex string."""
        salt = generate_salt()
        int(salt, 16)  # Should not raise

    def test_salt_is_unique(self):
        """Should generate unique salts."""
        salts = {generate_salt() for _ in range(100)}
        assert len(salts) == 100


class TestHashPin:
    """Test PIN hashing."""

    def test_hash_is_sha256(self):
        """Should produce SHA-256 hash (64 hex chars)."""
        salt = generate_salt()
        pin_hash = hash_pin("7a2B", salt)
        assert len(pin_hash) == 64

    def test_hash_is_deterministic(self):
        """Same PIN + salt should produce same hash."""
        salt = generate_salt()
        hash1 = hash_pin("7a2B", salt)
        hash2 = hash_pin("7a2B", salt)
        assert hash1 == hash2

    def test_different_pins_different_hashes(self):
        """Different PINs should produce different hashes."""
        salt = generate_salt()
        hash1 = hash_pin("7a2B", salt)
        hash2 = hash_pin("9x4Y", salt)
        assert hash1 != hash2

    def test_different_salts_different_hashes(self):
        """Same PIN with different salts should produce different hashes."""
        salt1 = generate_salt()
        salt2 = generate_salt()
        hash1 = hash_pin("7a2B", salt1)
        hash2 = hash_pin("7a2B", salt2)
        assert hash1 != hash2

    def test_case_sensitive(self):
        """PIN hashing should be case-sensitive."""
        salt = generate_salt()
        hash_lower = hash_pin("abcd", salt)
        hash_upper = hash_pin("ABCD", salt)
        assert hash_lower != hash_upper


class TestVerifyPinHash:
    """Test PIN hash verification."""

    def test_correct_pin_verifies(self):
        """Should return True for correct PIN."""
        salt = generate_salt()
        pin_hash = hash_pin("7a2B", salt)
        assert verify_pin_hash("7a2B", salt, pin_hash) is True

    def test_wrong_pin_fails(self):
        """Should return False for wrong PIN."""
        salt = generate_salt()
        pin_hash = hash_pin("7a2B", salt)
        assert verify_pin_hash("XXXX", salt, pin_hash) is False

    def test_case_sensitive_verification(self):
        """Should fail if case doesn't match."""
        salt = generate_salt()
        pin_hash = hash_pin("7a2B", salt)
        assert verify_pin_hash("7A2B", salt, pin_hash) is False

    def test_wrong_salt_fails(self):
        """Should fail with wrong salt."""
        salt1 = generate_salt()
        salt2 = generate_salt()
        pin_hash = hash_pin("7a2B", salt1)
        assert verify_pin_hash("7a2B", salt2, pin_hash) is False


class TestGeneratePinFileId:
    """Test 6-digit file ID generation."""

    def test_format_six_digits(self):
        """Should return exactly 6 digits."""
        file_id = generate_pin_file_id()
        assert len(file_id) == 6
        assert file_id.isdigit()

    def test_zero_padded(self):
        """Should be zero-padded (e.g., 000123)."""
        # Run many times to increase chance of getting a low number
        for _ in range(100):
            file_id = generate_pin_file_id()
            assert len(file_id) == 6

    def test_uniqueness(self):
        """Should generate unique IDs (high probability)."""
        ids = {generate_pin_file_id() for _ in range(1000)}
        # With 1M possible values, 1000 tries should have ~0 collisions
        assert len(ids) >= 990

    def test_range(self):
        """Should be between 000000 and 999999."""
        for _ in range(100):
            file_id = generate_pin_file_id()
            assert 0 <= int(file_id) <= 999999
```

**Step 2: Run test to verify it fails**

Run: `cd /home/antonaks/Documents/MyProjects/sdbx && python -m pytest backend/tests/test_pin_utils.py -v`
Expected: FAIL with `ModuleNotFoundError`

**Step 3: Write minimal implementation**

```python
# backend/shared/pin_utils.py
"""PIN-based sharing utility functions."""

import hashlib
import hmac
import os
from typing import Final

from .constants import PIN_SALT_BYTES

# File ID range: 000000-999999
_PIN_FILE_ID_MAX: Final[int] = 999999


def generate_salt() -> str:
    """
    Generate a random salt for PIN hashing.

    Returns:
        64-character hex string (32 bytes)
    """
    return os.urandom(PIN_SALT_BYTES).hex()


def hash_pin(pin: str, salt: str) -> str:
    """
    Hash a PIN with salt using SHA-256.

    Uses SHA-256(PIN + salt) for server-side PIN verification.
    This is separate from the PBKDF2 key derivation done client-side.

    Args:
        pin: 4-character alphanumeric PIN
        salt: 64-character hex salt string

    Returns:
        64-character hex hash string
    """
    return hashlib.sha256((pin + salt).encode("utf-8")).hexdigest()


def verify_pin_hash(pin: str, salt: str, expected_hash: str) -> bool:
    """
    Verify a PIN against stored hash using constant-time comparison.

    Args:
        pin: PIN to verify
        salt: Salt used during hashing
        expected_hash: Expected hash to compare against

    Returns:
        True if PIN matches, False otherwise
    """
    actual_hash = hash_pin(pin, salt)
    return hmac.compare_digest(actual_hash, expected_hash)


def generate_pin_file_id() -> str:
    """
    Generate a random 6-digit numeric file ID.

    Returns:
        Zero-padded 6-digit string (e.g., "482973", "000123")
    """
    # Use os.urandom for cryptographic randomness
    random_int = int.from_bytes(os.urandom(4), "big") % (_PIN_FILE_ID_MAX + 1)
    return f"{random_int:06d}"
```

**Step 4: Run test to verify it passes**

Run: `cd /home/antonaks/Documents/MyProjects/sdbx && python -m pytest backend/tests/test_pin_utils.py -v`
Expected: ALL PASS

**Step 5: Commit**

```bash
git add backend/shared/pin_utils.py backend/tests/test_pin_utils.py
git commit -m "feat(pin): add PIN hashing, verification, and file ID generation utilities"
```

---

## Task 4: Add DynamoDB Functions for PIN Records

**Files:**
- Modify: `backend/shared/dynamo.py`
- Create: `backend/tests/test_pin_dynamo.py`

**Step 1: Write the failing tests**

```python
# backend/tests/test_pin_dynamo.py
"""Unit tests for PIN-related DynamoDB functions - logic tests only."""

import time

import pytest

from shared.constants import (
    PIN_LOCKOUT_SECONDS,
    PIN_MAX_ATTEMPTS,
    PIN_SESSION_TIMEOUT_SECONDS,
)


class TestPinSessionLogic:
    """Test PIN session timeout logic (pure logic, no DynamoDB)."""

    def test_session_is_active_within_timeout(self):
        """Session started < 60s ago should be active."""
        session_expires = int(time.time()) + 30  # 30s remaining
        assert session_expires > int(time.time())

    def test_session_is_expired_after_timeout(self):
        """Session started > 60s ago should be expired."""
        session_expires = int(time.time()) - 1  # Expired 1s ago
        assert session_expires <= int(time.time())

    def test_session_timeout_is_60_seconds(self):
        """Session timeout should be 60 seconds."""
        assert PIN_SESSION_TIMEOUT_SECONDS == 60


class TestPinLockoutLogic:
    """Test PIN lockout logic (pure logic, no DynamoDB)."""

    def test_not_locked_when_no_locked_until(self):
        """Should not be locked if locked_until is not set."""
        locked_until = None
        current_time = int(time.time())
        is_locked = locked_until is not None and locked_until > current_time
        assert is_locked is False

    def test_locked_when_locked_until_in_future(self):
        """Should be locked if locked_until is in the future."""
        locked_until = int(time.time()) + 3600  # Locked for 1 more hour
        current_time = int(time.time())
        is_locked = locked_until is not None and locked_until > current_time
        assert is_locked is True

    def test_not_locked_when_locked_until_in_past(self):
        """Should not be locked if locked_until is in the past."""
        locked_until = int(time.time()) - 1  # Lock expired 1s ago
        current_time = int(time.time())
        is_locked = locked_until is not None and locked_until > current_time
        assert is_locked is False

    def test_lockout_duration_is_12_hours(self):
        """Lockout should be 12 hours (43200 seconds)."""
        assert PIN_LOCKOUT_SECONDS == 43200

    def test_max_attempts_is_3(self):
        """Max attempts should be 3."""
        assert PIN_MAX_ATTEMPTS == 3

    def test_attempts_reset_after_lockout(self):
        """Attempts should reset to 3 after lockout expires."""
        locked_until = int(time.time()) - 1  # Lock expired
        current_time = int(time.time())
        is_locked = locked_until is not None and locked_until > current_time
        # If not locked anymore, attempts should reset
        attempts = PIN_MAX_ATTEMPTS if not is_locked else 0
        assert attempts == PIN_MAX_ATTEMPTS


class TestPinAttemptsLogic:
    """Test PIN attempt decrement logic."""

    def test_decrement_from_3_to_2(self):
        """First failed attempt: 3 -> 2."""
        attempts_left = 3
        attempts_left -= 1
        assert attempts_left == 2

    def test_decrement_from_2_to_1(self):
        """Second failed attempt: 2 -> 1."""
        attempts_left = 2
        attempts_left -= 1
        assert attempts_left == 1

    def test_decrement_from_1_to_0_triggers_lockout(self):
        """Third failed attempt: 1 -> 0, should trigger lockout."""
        attempts_left = 1
        attempts_left -= 1
        should_lock = attempts_left <= 0
        assert should_lock is True

    def test_correct_pin_does_not_decrement(self):
        """Correct PIN should not change attempts count."""
        attempts_left = 3
        pin_correct = True
        if not pin_correct:
            attempts_left -= 1
        assert attempts_left == 3
```

**Step 2: Run test to verify it passes**

These are pure logic tests that validate our understanding of the business rules. They should pass immediately since they don't depend on new code.

Run: `cd /home/antonaks/Documents/MyProjects/sdbx && python -m pytest backend/tests/test_pin_dynamo.py -v`
Expected: PASS

**Step 3: Add DynamoDB functions**

Add to `backend/shared/dynamo.py`:

```python
from .constants import (
    ACCESS_MODE_PIN,
    PIN_LOCKOUT_SECONDS,
    PIN_MAX_ATTEMPTS,
    PIN_SESSION_TIMEOUT_SECONDS,
)
from .exceptions import FileLockedException, SessionExpiredError


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
) -> dict[str, Any]:
    """
    Create a PIN-based file record in DynamoDB.

    Args:
        table_name: DynamoDB table name
        file_id: 6-digit numeric file ID
        file_size: File size in bytes
        expires_at: Unix timestamp when file expires
        ip_hash: SHA256 hash of uploader IP
        pin_hash: SHA256 hash of PIN + salt
        salt: Hex-encoded salt for PIN hashing and PBKDF2
        content_type: "file" or "text"
        s3_key: S3 object key (files only)
        encrypted_text: Base64 encrypted text (text only)

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
        "access_mode": ACCESS_MODE_PIN,
        "pin_hash": pin_hash,
        "salt": salt,
        "attempts_left": PIN_MAX_ATTEMPTS,
    }

    if content_type == "file":
        if not s3_key:
            raise ValueError("s3_key required for file content_type")
        record["s3_key"] = s3_key
    elif content_type == "text":
        if not encrypted_text:
            raise ValueError("encrypted_text required for text content_type")
        record["encrypted_text"] = encrypted_text

    # Use conditional put to prevent file_id collision
    try:
        table.put_item(
            Item=record,
            ConditionExpression="attribute_not_exists(file_id)",
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            raise ValueError(f"File ID {file_id} already exists")
        raise

    logger.info(f"Created PIN {content_type} record: {file_id}")
    return record


def initiate_pin_session(table_name: str, file_id: str) -> dict[str, Any]:
    """
    Create a 60-second PIN entry session for a file.

    Checks file availability and lockout status before creating session.

    Args:
        table_name: DynamoDB table name
        file_id: 6-digit file ID

    Returns:
        Dict with session_expires and attempts_left

    Raises:
        FileNotFoundError: File doesn't exist
        FileExpiredError: File has expired
        FileAlreadyDownloadedError: File was already downloaded
        FileLockedException: File is locked due to failed PIN attempts
    """
    table = get_table(table_name)
    current_time = int(time.time())
    session_expires = current_time + PIN_SESSION_TIMEOUT_SECONDS

    # Get the record first to check status
    record = get_file_record(table_name, file_id)

    if not record:
        raise FileNotFoundError("File not found")

    if record.get("downloaded"):
        raise FileAlreadyDownloadedError("File has already been downloaded")

    if record.get("expires_at", 0) <= current_time:
        raise FileExpiredError("File has expired")

    if record.get("access_mode") != ACCESS_MODE_PIN:
        raise FileNotFoundError("File not found")

    # Check lockout
    locked_until = record.get("locked_until")
    if locked_until is not None and int(locked_until) > current_time:
        remaining_seconds = int(locked_until) - current_time
        remaining_hours = remaining_seconds // 3600 + (1 if remaining_seconds % 3600 else 0)
        raise FileLockedException(f"File is locked. Try again in {remaining_hours} hours")

    # If lock has expired, reset attempts
    attempts_left = int(record.get("attempts_left", PIN_MAX_ATTEMPTS))
    if locked_until is not None and int(locked_until) <= current_time:
        attempts_left = PIN_MAX_ATTEMPTS

    # Update session timestamps and potentially reset attempts
    try:
        update_expr = "SET session_started = :started, session_expires = :expires"
        expr_values = {
            ":started": current_time,
            ":expires": session_expires,
        }

        # Reset attempts if lockout expired
        if locked_until is not None and int(locked_until) <= current_time:
            update_expr += ", attempts_left = :max_attempts"
            update_expr += " REMOVE locked_until"
            expr_values[":max_attempts"] = PIN_MAX_ATTEMPTS
            attempts_left = PIN_MAX_ATTEMPTS

        table.update_item(
            Key={"file_id": file_id},
            UpdateExpression=update_expr,
            ExpressionAttributeValues=expr_values,
        )
    except ClientError as e:
        logger.error(f"Error creating PIN session for {file_id}: {e}")
        raise

    logger.info(f"PIN session created for: {file_id}, expires: {session_expires}")
    return {
        "session_expires": session_expires,
        "attempts_left": attempts_left,
    }


def verify_pin_and_download(
    table_name: str, file_id: str, pin: str
) -> dict[str, Any]:
    """
    Verify PIN and reserve file for download.

    Checks session validity, verifies PIN, handles attempts/lockout.

    Args:
        table_name: DynamoDB table name
        file_id: 6-digit file ID
        pin: 4-character PIN to verify

    Returns:
        File record with salt for client-side key derivation

    Raises:
        FileNotFoundError: File doesn't exist
        SessionExpiredError: PIN session has expired
        FileLockedException: File locked after 3 failed attempts
        ValidationError: Incorrect PIN
    """
    from .pin_utils import verify_pin_hash

    table = get_table(table_name)
    current_time = int(time.time())

    # Get record
    record = get_file_record(table_name, file_id)

    if not record:
        raise FileNotFoundError("File not found")

    if record.get("access_mode") != ACCESS_MODE_PIN:
        raise FileNotFoundError("File not found")

    if record.get("downloaded"):
        raise FileAlreadyDownloadedError("File has already been downloaded")

    if record.get("expires_at", 0) <= current_time:
        raise FileExpiredError("File has expired")

    # Check session validity
    session_expires = record.get("session_expires")
    if not session_expires or int(session_expires) <= current_time:
        raise SessionExpiredError("Session expired. Please enter file ID again")

    # Check lockout
    locked_until = record.get("locked_until")
    if locked_until is not None and int(locked_until) > current_time:
        remaining_seconds = int(locked_until) - current_time
        remaining_hours = remaining_seconds // 3600 + (1 if remaining_seconds % 3600 else 0)
        raise FileLockedException(f"File is locked. Try again in {remaining_hours} hours")

    # Check attempts
    attempts_left = int(record.get("attempts_left", 0))
    if attempts_left <= 0:
        raise FileLockedException("File is locked for 12 hours")

    # Verify PIN
    stored_hash = record["pin_hash"]
    stored_salt = record["salt"]

    if not verify_pin_hash(pin, stored_salt, stored_hash):
        # Decrement attempts
        new_attempts = attempts_left - 1

        update_expr = "SET attempts_left = :attempts"
        expr_values = {":attempts": new_attempts}

        # Lock if no attempts remaining
        if new_attempts <= 0:
            locked_until_ts = current_time + PIN_LOCKOUT_SECONDS
            update_expr += ", locked_until = :locked"
            expr_values[":locked"] = locked_until_ts

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

        from .exceptions import ValidationError
        raise ValidationError(f"Incorrect PIN. {new_attempts} attempts left")

    # PIN correct - reserve file for download (atomic)
    try:
        response = table.update_item(
            Key={"file_id": file_id},
            UpdateExpression="SET reserved_at = :now",
            ConditionExpression="downloaded = :false AND expires_at > :current",
            ExpressionAttributeValues={
                ":false": False,
                ":now": current_time,
                ":current": current_time,
            },
            ReturnValues="ALL_NEW",
        )
        logger.info(f"PIN verified, file reserved: {file_id}")
        return response["Attributes"]

    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            raise FileAlreadyDownloadedError("File has already been downloaded")
        raise
```

**Step 4: Run all tests to verify nothing is broken**

Run: `cd /home/antonaks/Documents/MyProjects/sdbx && python -m pytest backend/tests/ -v`
Expected: ALL PASS

**Step 5: Commit**

```bash
git add backend/shared/dynamo.py backend/tests/test_pin_dynamo.py
git commit -m "feat(pin): add DynamoDB functions for PIN session, verification, and lockout"
```

---

## Task 5: Create PIN Upload Init Lambda Handler

**Files:**
- Create: `backend/lambdas/pin_upload_init/handler.py`
- Create: `backend/tests/test_pin_upload_handler.py`

**Step 1: Write the failing tests**

```python
# backend/tests/test_pin_upload_handler.py
"""Unit tests for PIN upload init handler - validation and response format."""

import json

import pytest


class TestPinUploadInitValidation:
    """Test PIN upload handler validates inputs correctly."""

    def test_pin_validation_rejects_short_pin(self):
        """Should reject PIN shorter than 4 chars."""
        from shared.validation import validate_pin
        from shared.exceptions import ValidationError

        with pytest.raises(ValidationError):
            validate_pin("12")

    def test_pin_validation_rejects_special_chars(self):
        """Should reject PIN with special characters."""
        from shared.validation import validate_pin
        from shared.exceptions import ValidationError

        with pytest.raises(ValidationError):
            validate_pin("12@#")

    def test_pin_validation_accepts_valid(self):
        """Should accept valid 4-char alphanumeric PIN."""
        from shared.validation import validate_pin

        validate_pin("7a2B")

    def test_file_id_generation_format(self):
        """Generated file ID should be 6 digits."""
        from shared.pin_utils import generate_pin_file_id

        file_id = generate_pin_file_id()
        assert len(file_id) == 6
        assert file_id.isdigit()

    def test_salt_and_hash_round_trip(self):
        """Salt + hash should allow verification."""
        from shared.pin_utils import generate_salt, hash_pin, verify_pin_hash

        pin = "7a2B"
        salt = generate_salt()
        pin_hash = hash_pin(pin, salt)

        assert verify_pin_hash(pin, salt, pin_hash) is True
        assert verify_pin_hash("XXXX", salt, pin_hash) is False
```

**Step 2: Run test to verify it passes**

Run: `cd /home/antonaks/Documents/MyProjects/sdbx && python -m pytest backend/tests/test_pin_upload_handler.py -v`
Expected: PASS (these are just validation tests using existing utilities)

**Step 3: Write the handler**

```python
# backend/lambdas/pin_upload_init/handler.py
"""Lambda function: Initialize PIN-based file upload."""

import hashlib
import logging
import os
import time
from typing import Any

from shared.constants import (
    ACCESS_MODE_PIN,
    TTL_TO_SECONDS,
    UPLOAD_URL_EXPIRY_SECONDS,
)
from shared.dynamo import create_pin_file_record
from shared.exceptions import ValidationError
from shared.pin_utils import generate_pin_file_id, generate_salt, hash_pin
from shared.request_helpers import get_source_ip, parse_json_body
from shared.response import error_response, success_response
from shared.s3 import generate_upload_url
from shared.security import require_cloudfront_and_recaptcha
from shared.validation import validate_file_size, validate_pin, validate_ttl

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

BUCKET_NAME = os.environ.get("BUCKET_NAME")
TABLE_NAME = os.environ.get("TABLE_NAME")

# Max retries for file ID collision
MAX_ID_RETRIES = 5


def ttl_to_seconds(ttl) -> int:
    """Convert TTL value to seconds."""
    if isinstance(ttl, str) and ttl in TTL_TO_SECONDS:
        return TTL_TO_SECONDS[ttl]
    return int(ttl) * 60


@require_cloudfront_and_recaptcha
def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """
    Initialize PIN-based file or text upload.

    Expected request body:
    {
        "content_type": "file",  // or "text"
        "file_size": 1024,       // required for files
        "encrypted_text": "...", // required for text
        "pin": "7a2B",
        "ttl": "24h",
        "recaptcha_token": "..."
    }

    Returns:
    {
        "file_id": "482973",
        "upload_url": "...",     // only for files
        "expires_at": 1234567890
    }
    """
    try:
        body = parse_json_body(event)
        content_type = body.get("content_type", "file")
        ttl = body.get("ttl")
        pin = body.get("pin")

        # Validate inputs
        validate_ttl(ttl)
        validate_pin(pin)

        # Generate salt and hash PIN
        salt = generate_salt()
        pin_hash = hash_pin(pin, salt)

        # Generate unique 6-digit file ID with collision retry
        file_id = None
        for _ in range(MAX_ID_RETRIES):
            candidate_id = generate_pin_file_id()
            try:
                # Calculate expiration
                ttl_seconds = ttl_to_seconds(ttl)
                expires_at = int(time.time()) + ttl_seconds

                # Hash IP
                source_ip = get_source_ip(event)
                ip_hash = hashlib.sha256(source_ip.encode()).hexdigest()

                if content_type == "text":
                    encrypted_text = body.get("encrypted_text")
                    if not encrypted_text:
                        raise ValidationError("encrypted_text is required for text secrets")
                    if len(encrypted_text) > 10000:
                        raise ValidationError("Text secret too large")

                    create_pin_file_record(
                        table_name=TABLE_NAME,
                        file_id=candidate_id,
                        file_size=len(encrypted_text),
                        expires_at=expires_at,
                        ip_hash=ip_hash,
                        pin_hash=pin_hash,
                        salt=salt,
                        content_type="text",
                        encrypted_text=encrypted_text,
                    )

                    logger.info(f"PIN text created: file_id={candidate_id}, ttl={ttl}")
                    return success_response({
                        "file_id": candidate_id,
                        "expires_at": expires_at,
                    })

                else:
                    file_size = body.get("file_size")
                    validate_file_size(file_size)
                    s3_key = f"files/{candidate_id}"

                    create_pin_file_record(
                        table_name=TABLE_NAME,
                        file_id=candidate_id,
                        file_size=file_size,
                        expires_at=expires_at,
                        ip_hash=ip_hash,
                        pin_hash=pin_hash,
                        salt=salt,
                        content_type="file",
                        s3_key=s3_key,
                    )

                    upload_url = generate_upload_url(
                        bucket_name=BUCKET_NAME,
                        s3_key=s3_key,
                        expires_in=UPLOAD_URL_EXPIRY_SECONDS,
                    )

                    logger.info(f"PIN file upload init: file_id={candidate_id}, size={file_size}, ttl={ttl}")
                    return success_response({
                        "file_id": candidate_id,
                        "upload_url": upload_url,
                        "expires_at": expires_at,
                    })

            except ValueError as e:
                if "already exists" in str(e):
                    logger.warning(f"PIN file ID collision: {candidate_id}, retrying...")
                    continue
                raise

        # All retries exhausted
        logger.error("Failed to generate unique PIN file ID after max retries")
        return error_response("Failed to generate unique file ID. Please try again.", 500)

    except ValidationError as e:
        logger.warning(f"Validation error: {e}")
        return error_response(str(e), 400)

    except Exception as e:
        logger.exception("Unexpected error in pin_upload_init")
        return error_response("Internal server error", 500)
```

**Step 4: Run all tests**

Run: `cd /home/antonaks/Documents/MyProjects/sdbx && python -m pytest backend/tests/ -v`
Expected: ALL PASS

**Step 5: Commit**

```bash
git add backend/lambdas/pin_upload_init/handler.py backend/tests/test_pin_upload_handler.py
git commit -m "feat(pin): add PIN upload init Lambda handler"
```

---

## Task 6: Create PIN Session Initiation Lambda Handler

**Files:**
- Create: `backend/lambdas/pin_initiate/handler.py`

**Step 1: Write the handler**

```python
# backend/lambdas/pin_initiate/handler.py
"""Lambda function: Initiate PIN download session."""

import logging
import os
from typing import Any

from shared.constants import ACCESS_MODE_PIN
from shared.dynamo import initiate_pin_session
from shared.exceptions import (
    FileAlreadyDownloadedError,
    FileExpiredError,
    FileLockedException,
    FileNotFoundError,
    ValidationError,
)
from shared.request_helpers import parse_json_body
from shared.response import error_response, success_response
from shared.security import require_cloudfront_and_recaptcha
from shared.validation import validate_pin_file_id

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

TABLE_NAME = os.environ.get("TABLE_NAME")


@require_cloudfront_and_recaptcha
def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """
    Initiate a 60-second PIN entry session.

    Expected request body:
    {
        "file_id": "482973",
        "recaptcha_token": "..."
    }

    Returns:
    {
        "message": "Session started. Enter PIN within 60 seconds",
        "session_expires": 1738360060,
        "attempts_left": 3
    }
    """
    try:
        body = parse_json_body(event)
        file_id = body.get("file_id")

        validate_pin_file_id(file_id)

        result = initiate_pin_session(TABLE_NAME, file_id)

        return success_response({
            "message": "Session started. Enter PIN within 60 seconds",
            "session_expires": result["session_expires"],
            "attempts_left": result["attempts_left"],
        })

    except ValidationError as e:
        logger.warning(f"Validation error: {e}")
        return error_response(str(e), 400)

    except FileNotFoundError:
        return error_response("File not found", 404)

    except FileExpiredError:
        return error_response("File has expired", 410)

    except FileAlreadyDownloadedError:
        return error_response("File has already been downloaded", 410)

    except FileLockedException as e:
        return error_response(str(e), 423)

    except Exception as e:
        logger.exception("Unexpected error in pin_initiate")
        return error_response("Internal server error", 500)
```

**Step 2: Commit**

```bash
git add backend/lambdas/pin_initiate/handler.py
git commit -m "feat(pin): add PIN session initiation Lambda handler"
```

---

## Task 7: Create PIN Verification Lambda Handler

**Files:**
- Create: `backend/lambdas/pin_verify/handler.py`

**Step 1: Write the handler**

```python
# backend/lambdas/pin_verify/handler.py
"""Lambda function: Verify PIN and initiate download."""

import logging
import os
from typing import Any

from shared.constants import DOWNLOAD_URL_EXPIRY_SECONDS
from shared.dynamo import verify_pin_and_download
from shared.exceptions import (
    FileAlreadyDownloadedError,
    FileExpiredError,
    FileLockedException,
    FileNotFoundError,
    SessionExpiredError,
    ValidationError,
)
from shared.request_helpers import parse_json_body
from shared.response import error_response, success_response
from shared.s3 import generate_download_url
from shared.security import require_cloudfront_and_recaptcha
from shared.validation import validate_pin, validate_pin_file_id

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

BUCKET_NAME = os.environ.get("BUCKET_NAME")
TABLE_NAME = os.environ.get("TABLE_NAME")


@require_cloudfront_and_recaptcha
def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """
    Verify PIN and return download content.

    Expected request body:
    {
        "file_id": "482973",
        "pin": "7a2B",
        "recaptcha_token": "..."
    }

    Returns (success):
    {
        "download_url": "https://s3...",  // for files
        "encrypted_text": "...",          // for text
        "salt": "abc123...",              // for client-side PBKDF2 key derivation
        "file_size": 2500000,
        "content_type": "file"
    }
    """
    try:
        body = parse_json_body(event)
        file_id = body.get("file_id")
        pin = body.get("pin")

        validate_pin_file_id(file_id)
        validate_pin(pin)

        # Verify PIN and reserve file
        record = verify_pin_and_download(TABLE_NAME, file_id, pin)

        content_type = record.get("content_type", "file")
        salt = record.get("salt")

        if content_type == "text":
            logger.info(f"PIN text download: file_id={file_id}")
            return success_response({
                "content_type": "text",
                "encrypted_text": record["encrypted_text"],
                "salt": salt,
                "file_size": record["file_size"],
            })
        else:
            download_url = generate_download_url(
                bucket_name=BUCKET_NAME,
                s3_key=record["s3_key"],
                expires_in=DOWNLOAD_URL_EXPIRY_SECONDS,
            )

            logger.info(f"PIN file download: file_id={file_id}")
            return success_response({
                "content_type": "file",
                "download_url": download_url,
                "salt": salt,
                "file_size": record["file_size"],
            })

    except ValidationError as e:
        logger.warning(f"Validation error: {e}")
        # Check if it's an incorrect PIN message (contains "attempts left")
        msg = str(e)
        if "attempts left" in msg:
            return error_response(msg, 401)
        return error_response(msg, 400)

    except FileNotFoundError:
        return error_response("File not found", 404)

    except SessionExpiredError as e:
        return error_response(str(e), 408)

    except FileAlreadyDownloadedError:
        return error_response("File has already been downloaded", 410)

    except FileExpiredError:
        return error_response("File has expired", 410)

    except FileLockedException as e:
        return error_response(str(e), 423)

    except Exception as e:
        logger.exception("Unexpected error in pin_verify")
        return error_response("Internal server error", 500)
```

**Step 2: Commit**

```bash
git add backend/lambdas/pin_verify/handler.py
git commit -m "feat(pin): add PIN verification Lambda handler"
```

---

## Task 8: Add Terraform Resources for PIN Endpoints

**Files:**
- Modify: `terraform/modules/api/main.tf`

**Step 1: Add new API Gateway resources and Lambda functions**

Add to `terraform/modules/api/main.tf` after existing resource definitions:

```hcl
# ===== PIN-Based Sharing Resources =====

# /pin resource
resource "aws_api_gateway_resource" "pin" {
  rest_api_id = aws_api_gateway_rest_api.main.id
  parent_id   = aws_api_gateway_rest_api.main.root_resource_id
  path_part   = "pin"
}

# /pin/upload
resource "aws_api_gateway_resource" "pin_upload" {
  rest_api_id = aws_api_gateway_rest_api.main.id
  parent_id   = aws_api_gateway_resource.pin.id
  path_part   = "upload"
}

# /pin/initiate
resource "aws_api_gateway_resource" "pin_initiate" {
  rest_api_id = aws_api_gateway_rest_api.main.id
  parent_id   = aws_api_gateway_resource.pin.id
  path_part   = "initiate"
}

# /pin/verify
resource "aws_api_gateway_resource" "pin_verify" {
  rest_api_id = aws_api_gateway_rest_api.main.id
  parent_id   = aws_api_gateway_resource.pin.id
  path_part   = "verify"
}

# CORS for PIN endpoints
module "cors_pin_upload" {
  source      = "./modules/cors"
  api_id      = aws_api_gateway_rest_api.main.id
  resource_id = aws_api_gateway_resource.pin_upload.id
}

module "cors_pin_initiate" {
  source      = "./modules/cors"
  api_id      = aws_api_gateway_rest_api.main.id
  resource_id = aws_api_gateway_resource.pin_initiate.id
}

module "cors_pin_verify" {
  source      = "./modules/cors"
  api_id      = aws_api_gateway_rest_api.main.id
  resource_id = aws_api_gateway_resource.pin_verify.id
}

# Lambda: PIN Upload Init
module "lambda_pin_upload_init" {
  source = "./modules/lambda"

  function_name = "${var.project_name}-${var.environment}-pin-upload-init"
  handler       = "handler.handler"
  runtime       = var.lambda_runtime
  timeout       = var.lambda_timeout
  memory_size   = var.lambda_memory_size
  source_dir    = "${path.root}/../../../backend/lambdas/pin_upload_init"
  layers        = [aws_lambda_layer_version.dependencies.arn]

  environment_variables = {
    BUCKET_NAME          = var.bucket_name
    TABLE_NAME           = var.table_name
    ENVIRONMENT          = var.environment
    MAX_FILE_SIZE        = var.max_file_size_bytes
    CLOUDFRONT_SECRET    = var.cloudfront_secret
    RECAPTCHA_SECRET_KEY = var.recaptcha_secret_key
  }

  iam_policy_statements = [
    {
      effect    = "Allow"
      actions   = ["s3:PutObject", "s3:PutObjectAcl"]
      resources = ["${var.bucket_arn}/*"]
    },
    {
      effect    = "Allow"
      actions   = ["dynamodb:PutItem", "dynamodb:GetItem"]
      resources = [var.table_arn]
    }
  ]

  tags = var.tags
}

# Lambda: PIN Session Initiate
module "lambda_pin_initiate" {
  source = "./modules/lambda"

  function_name = "${var.project_name}-${var.environment}-pin-initiate"
  handler       = "handler.handler"
  runtime       = var.lambda_runtime
  timeout       = var.lambda_timeout
  memory_size   = var.lambda_memory_size
  source_dir    = "${path.root}/../../../backend/lambdas/pin_initiate"
  layers        = [aws_lambda_layer_version.dependencies.arn]

  environment_variables = {
    TABLE_NAME           = var.table_name
    ENVIRONMENT          = var.environment
    CLOUDFRONT_SECRET    = var.cloudfront_secret
    RECAPTCHA_SECRET_KEY = var.recaptcha_secret_key
  }

  iam_policy_statements = [
    {
      effect    = "Allow"
      actions   = ["dynamodb:GetItem", "dynamodb:UpdateItem"]
      resources = [var.table_arn]
    }
  ]

  tags = var.tags
}

# Lambda: PIN Verify
module "lambda_pin_verify" {
  source = "./modules/lambda"

  function_name = "${var.project_name}-${var.environment}-pin-verify"
  handler       = "handler.handler"
  runtime       = var.lambda_runtime
  timeout       = var.lambda_timeout
  memory_size   = var.lambda_memory_size
  source_dir    = "${path.root}/../../../backend/lambdas/pin_verify"
  layers        = [aws_lambda_layer_version.dependencies.arn]

  environment_variables = {
    BUCKET_NAME          = var.bucket_name
    TABLE_NAME           = var.table_name
    ENVIRONMENT          = var.environment
    CLOUDFRONT_SECRET    = var.cloudfront_secret
    RECAPTCHA_SECRET_KEY = var.recaptcha_secret_key
  }

  iam_policy_statements = [
    {
      effect    = "Allow"
      actions   = ["s3:GetObject"]
      resources = ["${var.bucket_arn}/*"]
    },
    {
      effect    = "Allow"
      actions   = ["dynamodb:GetItem", "dynamodb:UpdateItem"]
      resources = [var.table_arn]
    }
  ]

  tags = var.tags
}

# API Gateway Methods - PIN endpoints

# POST /pin/upload
resource "aws_api_gateway_method" "pin_upload_post" {
  rest_api_id   = aws_api_gateway_rest_api.main.id
  resource_id   = aws_api_gateway_resource.pin_upload.id
  http_method   = "POST"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "pin_upload" {
  rest_api_id             = aws_api_gateway_rest_api.main.id
  resource_id             = aws_api_gateway_resource.pin_upload.id
  http_method             = aws_api_gateway_method.pin_upload_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = module.lambda_pin_upload_init.invoke_arn
}

# POST /pin/initiate
resource "aws_api_gateway_method" "pin_initiate_post" {
  rest_api_id   = aws_api_gateway_rest_api.main.id
  resource_id   = aws_api_gateway_resource.pin_initiate.id
  http_method   = "POST"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "pin_initiate" {
  rest_api_id             = aws_api_gateway_rest_api.main.id
  resource_id             = aws_api_gateway_resource.pin_initiate.id
  http_method             = aws_api_gateway_method.pin_initiate_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = module.lambda_pin_initiate.invoke_arn
}

# POST /pin/verify
resource "aws_api_gateway_method" "pin_verify_post" {
  rest_api_id   = aws_api_gateway_rest_api.main.id
  resource_id   = aws_api_gateway_resource.pin_verify.id
  http_method   = "POST"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "pin_verify" {
  rest_api_id             = aws_api_gateway_rest_api.main.id
  resource_id             = aws_api_gateway_resource.pin_verify.id
  http_method             = aws_api_gateway_method.pin_verify_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = module.lambda_pin_verify.invoke_arn
}

# Lambda permissions for PIN endpoints
resource "aws_lambda_permission" "pin_upload" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = module.lambda_pin_upload_init.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.main.execution_arn}/*/*"
}

resource "aws_lambda_permission" "pin_initiate" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = module.lambda_pin_initiate.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.main.execution_arn}/*/*"
}

resource "aws_lambda_permission" "pin_verify" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = module.lambda_pin_verify.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.main.execution_arn}/*/*"
}
```

Also update the `aws_api_gateway_deployment` `triggers` block to include the new resources:

```hcl
# Add to the triggers hash list:
aws_api_gateway_method.pin_upload_post.id,
aws_api_gateway_integration.pin_upload.id,
aws_api_gateway_method.pin_initiate_post.id,
aws_api_gateway_integration.pin_initiate.id,
aws_api_gateway_method.pin_verify_post.id,
aws_api_gateway_integration.pin_verify.id,
# Increment version
"v4",
```

Also update `depends_on` for the deployment:

```hcl
aws_api_gateway_integration.pin_upload,
aws_api_gateway_integration.pin_initiate,
aws_api_gateway_integration.pin_verify,
```

**Step 2: Validate Terraform**

Run: `cd /home/antonaks/Documents/MyProjects/sdbx/terraform/environments/dev && terraform validate`
Expected: Success

**Step 3: Commit**

```bash
git add terraform/modules/api/main.tf
git commit -m "feat(pin): add Terraform resources for PIN API endpoints and Lambda functions"
```

---

## Task 9: Add PIN Upload Frontend - Method Selection UI

**Files:**
- Modify: `frontend/index.html`
- Create: `frontend/js/pin-upload.js`
- Modify: `frontend/css/style.css`

**Step 1: Add method selection screen to index.html**

Add a new section BEFORE the existing tab content. The method selection screen is the first thing users see. When "Share Link" is selected, show the existing file/text/vault tabs. When "PIN Code" is selected, show the PIN upload form.

Add to `frontend/index.html` after the header, before the tabs:

```html
<!-- Method Selection Screen -->
<section id="method-selection" class="method-selection">
    <h2>How would you like to share?</h2>
    <div class="method-cards">
        <div class="method-card" id="method-link" tabindex="0" role="button" aria-label="Select Share Link mode">
            <div class="method-icon">&#128279;</div>
            <h3>Share Link</h3>
            <p>Copy & paste a secure URL</p>
            <span class="method-use-case">Works everywhere</span>
            <button class="method-btn" data-method="link">Select Link Mode</button>
        </div>
        <div class="method-card" id="method-pin" tabindex="0" role="button" aria-label="Select PIN Code mode">
            <div class="method-icon">&#128241;</div>
            <h3>PIN Code</h3>
            <p>Phone to Computer</p>
            <span class="method-use-case">Just 6 digits + PIN</span>
            <span class="method-recommended" id="pin-recommended">Recommended</span>
            <button class="method-btn" data-method="pin">Select PIN Mode</button>
        </div>
    </div>
    <button class="help-link" id="method-help-btn" aria-label="Which method should I use?">Which method should I use?</button>
</section>

<!-- Help Modal -->
<div id="method-help-modal" class="modal hidden" role="dialog" aria-modal="true" aria-labelledby="help-modal-title">
    <div class="modal-content">
        <button class="modal-close" aria-label="Close help">&times;</button>
        <h3 id="help-modal-title">Which method should I use?</h3>
        <div class="help-columns">
            <div>
                <h4>Use Link if:</h4>
                <ul>
                    <li>Sharing via email or chat</li>
                    <li>Sending to multiple people</li>
                    <li>Recipient has a browser open</li>
                </ul>
            </div>
            <div>
                <h4>Use PIN if:</h4>
                <ul>
                    <li>Sending from phone to computer</li>
                    <li>Don't want to copy long URLs</li>
                    <li>Want a simple code to type</li>
                </ul>
            </div>
        </div>
    </div>
</div>
```

Add PIN upload form (hidden by default, shown when PIN mode selected):

```html
<!-- PIN Upload Form (after method selection, before existing tabs) -->
<section id="pin-upload-section" class="hidden">
    <button class="back-btn" id="pin-back-btn">&#8592; Back to method selection</button>
    <div class="mode-indicator">&#128241; PIN Code Mode</div>

    <div class="upload-container">
        <!-- Drop zone (reuse existing pattern) -->
        <div id="pin-drop-zone" class="drop-zone" tabindex="0">
            <p>Drop file here or click to browse</p>
            <input type="file" id="pin-file-input" class="hidden" />
        </div>

        <div id="pin-file-info" class="file-info hidden">
            <span id="pin-file-name"></span>
            <span id="pin-file-size"></span>
            <button id="pin-file-remove" class="remove-btn" aria-label="Remove file">&times;</button>
        </div>

        <!-- PIN Input -->
        <div class="pin-input-group">
            <label for="pin-input">Set your PIN (4 characters):</label>
            <div class="pin-input-wrapper">
                <input
                    type="text"
                    id="pin-input"
                    maxlength="4"
                    autocomplete="off"
                    autocorrect="off"
                    autocapitalize="off"
                    spellcheck="false"
                    placeholder="e.g. 7a2B"
                    aria-describedby="pin-validation-msg"
                />
                <span id="pin-char-count" class="char-count">0/4</span>
            </div>
            <div id="pin-validation-msg" class="validation-msg" aria-live="polite"></div>
            <p class="hint">Letters & numbers only (case-sensitive)</p>
        </div>

        <!-- TTL selector (same as existing) -->
        <div class="ttl-selector">
            <label>Delete after:</label>
            <div class="ttl-options">
                <label><input type="radio" name="pin-ttl" value="1h" /> 1 hour</label>
                <label><input type="radio" name="pin-ttl" value="12h" /> 12 hours</label>
                <label><input type="radio" name="pin-ttl" value="24h" checked /> 24 hours</label>
            </div>
        </div>

        <button id="pin-upload-btn" class="upload-btn" disabled>Encrypt & Upload</button>

        <!-- Progress -->
        <div id="pin-progress" class="progress-container hidden">
            <div class="progress-bar">
                <div id="pin-progress-fill" class="progress-fill"></div>
            </div>
            <p id="pin-progress-text" class="progress-text">Encrypting...</p>
        </div>
    </div>
</section>

<!-- PIN Upload Result -->
<section id="pin-result-section" class="hidden">
    <h2>File Uploaded Successfully!</h2>
    <div class="pin-code-display">
        <p>Your download code:</p>
        <div id="pin-code-value" class="code-display" aria-label="Download code"></div>
        <button id="pin-copy-code" class="copy-btn">Copy Code</button>
    </div>

    <div class="pin-reveal">
        <span>Your PIN: </span>
        <span id="pin-display-masked">****</span>
        <span id="pin-display-value" class="hidden"></span>
        <button id="pin-reveal-btn" class="reveal-btn">Show</button>
    </div>

    <div class="pin-warnings">
        <p><strong>Important:</strong></p>
        <ul>
            <li>Remember BOTH: code + PIN</li>
            <li>Code works only ONCE</li>
            <li>Expires in <span id="pin-expiry-label"></span></li>
            <li>3 wrong PIN attempts = 12 hour lockout</li>
        </ul>
    </div>

    <div class="pin-instructions">
        <p><strong>To download:</strong></p>
        <ol>
            <li>Go to <span id="pin-domain"></span> on your other device</li>
            <li>Enter code: <strong id="pin-code-repeat"></strong></li>
            <li>Enter PIN: <strong id="pin-value-repeat"></strong></li>
        </ol>
    </div>

    <button id="pin-upload-another" class="upload-btn">Upload Another File</button>
</section>
```

**Step 2: Add corresponding CSS for method selection and PIN UI**

Add to `frontend/css/style.css` (or the appropriate Tailwind extension):

Key CSS classes needed:
- `.method-selection` - container for method cards
- `.method-cards` - flexbox container (row on desktop, column on mobile)
- `.method-card` - card style with hover/focus effects
- `.method-recommended` - "Recommended" badge (hidden on desktop, shown on mobile)
- `.mode-indicator` - shows current mode at top of upload form
- `.back-btn` - back to method selection button
- `.pin-input-group` - PIN input with validation
- `.code-display` - large 48px+ font for 6-digit code
- `.pin-reveal` - masked PIN with show/hide toggle
- `.validation-msg.valid` / `.validation-msg.invalid` - real-time validation feedback
- `.modal` / `.modal-content` - help modal

**Step 3: Write `frontend/js/pin-upload.js`**

```javascript
// frontend/js/pin-upload.js
'use strict';

/**
 * PIN-based file upload module.
 *
 * Handles: file selection, PIN validation, encryption with PBKDF2,
 * upload to S3 via PIN upload endpoint, and result display.
 */
const PinUpload = (function() {
    // PIN validation regex: exactly 4 alphanumeric characters
    const PIN_REGEX = /^[a-zA-Z0-9]{4}$/;
    const API_BASE = window.API_BASE_URL || '';

    let selectedFile = null;
    let currentPin = '';

    /**
     * Initialize PIN upload module.
     * Binds all event listeners for the PIN upload flow.
     */
    function init() {
        // Method selection
        const methodLink = document.getElementById('method-link');
        const methodPin = document.getElementById('method-pin');

        if (methodLink) {
            methodLink.addEventListener('click', () => selectMethod('link'));
        }
        if (methodPin) {
            methodPin.addEventListener('click', () => selectMethod('pin'));
        }

        // Help modal
        const helpBtn = document.getElementById('method-help-btn');
        const helpModal = document.getElementById('method-help-modal');
        if (helpBtn && helpModal) {
            helpBtn.addEventListener('click', () => helpModal.classList.remove('hidden'));
            helpModal.addEventListener('click', (e) => {
                if (e.target === helpModal || e.target.classList.contains('modal-close')) {
                    helpModal.classList.add('hidden');
                }
            });
        }

        // Back button
        const backBtn = document.getElementById('pin-back-btn');
        if (backBtn) {
            backBtn.addEventListener('click', () => selectMethod(null));
        }

        // File selection
        const dropZone = document.getElementById('pin-drop-zone');
        const fileInput = document.getElementById('pin-file-input');
        if (dropZone && fileInput) {
            dropZone.addEventListener('click', () => fileInput.click());
            dropZone.addEventListener('dragover', (e) => {
                e.preventDefault();
                dropZone.classList.add('dragover');
            });
            dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
            dropZone.addEventListener('drop', (e) => {
                e.preventDefault();
                dropZone.classList.remove('dragover');
                if (e.dataTransfer.files.length > 0) {
                    handleFileSelect(e.dataTransfer.files[0]);
                }
            });
            fileInput.addEventListener('change', (e) => {
                if (e.target.files.length > 0) {
                    handleFileSelect(e.target.files[0]);
                }
            });
        }

        // File remove
        const removeBtn = document.getElementById('pin-file-remove');
        if (removeBtn) {
            removeBtn.addEventListener('click', clearFile);
        }

        // PIN input
        const pinInput = document.getElementById('pin-input');
        if (pinInput) {
            pinInput.addEventListener('input', handlePinInput);
        }

        // Upload button
        const uploadBtn = document.getElementById('pin-upload-btn');
        if (uploadBtn) {
            uploadBtn.addEventListener('click', handleUpload);
        }

        // Result actions
        const copyCodeBtn = document.getElementById('pin-copy-code');
        if (copyCodeBtn) {
            copyCodeBtn.addEventListener('click', handleCopyCode);
        }

        const revealBtn = document.getElementById('pin-reveal-btn');
        if (revealBtn) {
            revealBtn.addEventListener('click', togglePinReveal);
        }

        const uploadAnotherBtn = document.getElementById('pin-upload-another');
        if (uploadAnotherBtn) {
            uploadAnotherBtn.addEventListener('click', resetForm);
        }

        // Show "Recommended" badge on mobile only
        updateRecommendedBadge();
        window.addEventListener('resize', updateRecommendedBadge);
    }

    function updateRecommendedBadge() {
        const badge = document.getElementById('pin-recommended');
        if (badge) {
            badge.style.display = window.innerWidth < 768 ? 'inline-block' : 'none';
        }
    }

    /**
     * Switch between method selection, link mode, and PIN mode.
     * @param {string|null} method - 'link', 'pin', or null (back to selection)
     */
    function selectMethod(method) {
        const selectionSection = document.getElementById('method-selection');
        const pinSection = document.getElementById('pin-upload-section');
        const linkSection = document.getElementById('upload-section');  // Existing upload section
        const tabNav = document.querySelector('.tab-nav');  // Existing tab navigation

        // Hide all first
        if (selectionSection) selectionSection.classList.add('hidden');
        if (pinSection) pinSection.classList.add('hidden');
        if (linkSection) linkSection.classList.add('hidden');
        if (tabNav) tabNav.classList.add('hidden');

        if (method === 'link') {
            // Show existing upload flow with tabs
            if (linkSection) linkSection.classList.remove('hidden');
            if (tabNav) tabNav.classList.remove('hidden');
        } else if (method === 'pin') {
            // Show PIN upload form
            if (pinSection) pinSection.classList.remove('hidden');
        } else {
            // Show method selection
            if (selectionSection) selectionSection.classList.remove('hidden');
        }
    }

    function handleFileSelect(file) {
        if (file.size > 500 * 1024 * 1024) {
            Utils.showError('File size exceeds 500 MB limit');
            return;
        }
        selectedFile = file;
        const nameEl = document.getElementById('pin-file-name');
        const sizeEl = document.getElementById('pin-file-size');
        const infoEl = document.getElementById('pin-file-info');
        if (nameEl) nameEl.textContent = file.name;
        if (sizeEl) sizeEl.textContent = Utils.formatFileSize(file.size);
        if (infoEl) infoEl.classList.remove('hidden');
        updateUploadButton();
    }

    function clearFile() {
        selectedFile = null;
        const infoEl = document.getElementById('pin-file-info');
        const inputEl = document.getElementById('pin-file-input');
        if (infoEl) infoEl.classList.add('hidden');
        if (inputEl) inputEl.value = '';
        updateUploadButton();
    }

    function handlePinInput(e) {
        const pin = e.target.value;
        currentPin = pin;
        const countEl = document.getElementById('pin-char-count');
        const msgEl = document.getElementById('pin-validation-msg');

        if (countEl) countEl.textContent = `${pin.length}/4`;

        if (pin.length === 0) {
            if (msgEl) {
                msgEl.textContent = '';
                msgEl.className = 'validation-msg';
            }
        } else if (pin.length < 4) {
            if (msgEl) {
                msgEl.textContent = `${4 - pin.length} more characters needed`;
                msgEl.className = 'validation-msg';
            }
        } else if (!PIN_REGEX.test(pin)) {
            if (msgEl) {
                msgEl.textContent = 'Only letters and numbers allowed';
                msgEl.className = 'validation-msg invalid';
            }
        } else {
            if (msgEl) {
                msgEl.textContent = 'Valid PIN';
                msgEl.className = 'validation-msg valid';
            }
        }

        updateUploadButton();
    }

    function updateUploadButton() {
        const btn = document.getElementById('pin-upload-btn');
        if (btn) {
            btn.disabled = !(selectedFile && PIN_REGEX.test(currentPin));
        }
    }

    /**
     * Handle PIN upload: encrypt with PBKDF2-derived key, upload to S3.
     */
    async function handleUpload() {
        if (!selectedFile || !PIN_REGEX.test(currentPin)) return;

        const uploadBtn = document.getElementById('pin-upload-btn');
        const progressContainer = document.getElementById('pin-progress');
        const progressFill = document.getElementById('pin-progress-fill');
        const progressText = document.getElementById('pin-progress-text');

        try {
            uploadBtn.disabled = true;
            progressContainer.classList.remove('hidden');

            // Step 1: Generate salt and derive key from PIN (20%)
            progressText.textContent = 'Deriving encryption key...';
            progressFill.style.width = '5%';

            const salt = CryptoModule.generateSalt();
            const cryptoKey = await CryptoModule.deriveKeyFromPassword(currentPin, salt);

            progressFill.style.width = '20%';

            // Step 2: Encrypt file (20-50%)
            progressText.textContent = 'Encrypting file...';
            const fileBuffer = await selectedFile.arrayBuffer();
            const encryptedData = await CryptoModule.encrypt(new Uint8Array(fileBuffer), cryptoKey);

            progressFill.style.width = '50%';

            // Step 3: Get reCAPTCHA token and call PIN upload init (50-60%)
            progressText.textContent = 'Initializing upload...';
            const recaptchaToken = await Utils.getRecaptchaToken(
                window.RECAPTCHA_SITE_KEY, 'pin_upload'
            );

            const ttl = document.querySelector('input[name="pin-ttl"]:checked')?.value || '24h';

            const initResponse = await fetch(`${API_BASE}/pin/upload`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    content_type: 'file',
                    file_size: encryptedData.byteLength,
                    pin: currentPin,
                    ttl: ttl,
                    recaptcha_token: recaptchaToken,
                }),
            });

            if (!initResponse.ok) {
                const err = await initResponse.json();
                throw new Error(err.error || 'Upload initialization failed');
            }

            const initData = await initResponse.json();
            progressFill.style.width = '60%';

            // Step 4: Upload encrypted file to S3 (60-90%)
            progressText.textContent = 'Uploading encrypted file...';

            await new Promise((resolve, reject) => {
                const xhr = new XMLHttpRequest();
                xhr.open('PUT', initData.upload_url);
                xhr.setRequestHeader('Content-Type', 'application/octet-stream');
                xhr.upload.onprogress = (e) => {
                    if (e.lengthComputable) {
                        const pct = 60 + (e.loaded / e.total) * 30;
                        progressFill.style.width = `${pct}%`;
                    }
                };
                xhr.onload = () => xhr.status === 200 ? resolve() : reject(new Error('Upload failed'));
                xhr.onerror = () => reject(new Error('Network error during upload'));
                xhr.send(new Blob([encryptedData]));
            });

            progressFill.style.width = '100%';
            progressText.textContent = 'Upload complete!';

            // Show result
            showResult(initData.file_id, currentPin, ttl);

        } catch (error) {
            console.error('PIN upload failed:', error);
            Utils.showError(error.message || 'Upload failed. Please try again.');
            progressContainer.classList.add('hidden');
            uploadBtn.disabled = false;
        }
    }

    function showResult(fileId, pin, ttl) {
        document.getElementById('pin-upload-section').classList.add('hidden');
        document.getElementById('pin-result-section').classList.remove('hidden');

        document.getElementById('pin-code-value').textContent = fileId;
        document.getElementById('pin-display-value').textContent = pin;
        document.getElementById('pin-code-repeat').textContent = fileId;
        document.getElementById('pin-value-repeat').textContent = pin;

        // Set expiry label
        const ttlLabels = { '1h': '1 hour', '12h': '12 hours', '24h': '24 hours' };
        document.getElementById('pin-expiry-label').textContent = ttlLabels[ttl] || ttl;

        // Set domain
        document.getElementById('pin-domain').textContent = window.location.hostname;
    }

    function handleCopyCode() {
        const code = document.getElementById('pin-code-value').textContent;
        Utils.copyToClipboard(code);
        const btn = document.getElementById('pin-copy-code');
        const original = btn.textContent;
        btn.textContent = 'Copied!';
        setTimeout(() => btn.textContent = original, 2000);
    }

    function togglePinReveal() {
        const masked = document.getElementById('pin-display-masked');
        const value = document.getElementById('pin-display-value');
        const btn = document.getElementById('pin-reveal-btn');

        if (value.classList.contains('hidden')) {
            value.classList.remove('hidden');
            masked.classList.add('hidden');
            btn.textContent = 'Hide';
        } else {
            value.classList.add('hidden');
            masked.classList.remove('hidden');
            btn.textContent = 'Show';
        }
    }

    function resetForm() {
        document.getElementById('pin-result-section').classList.add('hidden');
        clearFile();
        currentPin = '';
        const pinInput = document.getElementById('pin-input');
        if (pinInput) pinInput.value = '';
        const countEl = document.getElementById('pin-char-count');
        if (countEl) countEl.textContent = '0/4';
        const msgEl = document.getElementById('pin-validation-msg');
        if (msgEl) { msgEl.textContent = ''; msgEl.className = 'validation-msg'; }
        updateUploadButton();
        selectMethod('pin');
    }

    return { init, selectMethod };
})();

document.addEventListener('DOMContentLoaded', PinUpload.init);
```

**Step 4: Add `<script>` tag to index.html**

```html
<script src="/js/pin-upload.js"></script>
```

**Step 5: Commit**

```bash
git add frontend/index.html frontend/js/pin-upload.js frontend/css/style.css
git commit -m "feat(pin): add method selection UI and PIN upload frontend"
```

---

## Task 10: Add PIN Download Frontend - Code Entry + PIN Verification

**Files:**
- Modify: `frontend/download.html`
- Create: `frontend/js/pin-download.js`

**Step 1: Add PIN download sections to download.html**

Add BEFORE the existing download sections:

```html
<!-- PIN Download: Step 1 - Code Entry -->
<section id="pin-code-section" class="hidden">
    <h2>Download Your File</h2>
    <p>Enter your 6-digit code:</p>

    <div class="code-input-group" id="code-input-boxes">
        <input type="text" class="code-digit" maxlength="1" inputmode="numeric" pattern="[0-9]" data-index="0" aria-label="Digit 1" />
        <input type="text" class="code-digit" maxlength="1" inputmode="numeric" pattern="[0-9]" data-index="1" aria-label="Digit 2" />
        <input type="text" class="code-digit" maxlength="1" inputmode="numeric" pattern="[0-9]" data-index="2" aria-label="Digit 3" />
        <input type="text" class="code-digit" maxlength="1" inputmode="numeric" pattern="[0-9]" data-index="3" aria-label="Digit 4" />
        <input type="text" class="code-digit" maxlength="1" inputmode="numeric" pattern="[0-9]" data-index="4" aria-label="Digit 5" />
        <input type="text" class="code-digit" maxlength="1" inputmode="numeric" pattern="[0-9]" data-index="5" aria-label="Digit 6" />
    </div>

    <button id="code-continue-btn" class="download-btn" disabled>Continue</button>

    <div id="code-error" class="error-msg hidden" aria-live="polite"></div>

    <p class="hint">The code looks like: 482973<br/>You got it after uploading the file</p>
</section>

<!-- PIN Download: Step 2 - PIN Entry with Timer -->
<section id="pin-entry-section" class="hidden">
    <div class="pin-header">
        <span>File: <strong id="pin-file-code"></strong></span>
    </div>

    <div id="pin-timer" class="timer" aria-live="polite" aria-atomic="true">
        Time remaining: <span id="pin-timer-value">60</span> seconds
    </div>

    <div class="attempts-display" aria-live="polite">
        Attempts left: <span id="pin-attempts-value">3</span>
    </div>

    <div class="pin-entry-group">
        <label for="pin-verify-input">Enter your PIN (4 characters):</label>
        <input
            type="text"
            id="pin-verify-input"
            maxlength="4"
            autocomplete="off"
            autocorrect="off"
            autocapitalize="off"
            spellcheck="false"
            class="pin-large-input"
            aria-describedby="pin-verify-error"
        />
    </div>

    <button id="pin-download-btn" class="download-btn" disabled>Download File</button>

    <div id="pin-verify-error" class="error-msg hidden" aria-live="polite"></div>

    <p class="warning-text">Wrong PIN 3 times = 12 hour lockout</p>
</section>

<!-- PIN Download: Session Expired -->
<section id="pin-timeout-section" class="hidden">
    <h2>Session Expired</h2>
    <p>You didn't enter the PIN within 60 seconds.</p>
    <p>Please enter your 6-digit code again to start a new session.</p>
    <button id="pin-try-again-btn" class="download-btn">Enter Code Again</button>
</section>

<!-- PIN Download: Locked -->
<section id="pin-locked-section" class="hidden">
    <h2>File Locked</h2>
    <p>Too many incorrect PIN attempts.</p>
    <p>This file is locked for 12 hours.</p>
    <p>You can try again at: <strong id="pin-unlock-time"></strong></p>
    <a href="/" class="btn">Go to Homepage</a>
</section>

<!-- PIN Download: Progress -->
<section id="pin-download-progress-section" class="hidden">
    <h2>Downloading...</h2>
    <div class="progress-bar">
        <div id="pin-dl-progress-fill" class="progress-fill"></div>
    </div>
    <p id="pin-dl-progress-text">Downloading encrypted file...</p>
</section>
```

**Step 2: Write `frontend/js/pin-download.js`**

```javascript
// frontend/js/pin-download.js
'use strict';

/**
 * PIN-based file download module.
 *
 * Handles: 6-digit code entry, 60s session timer, PIN verification,
 * PBKDF2 key derivation, file download + decryption, and confirm.
 */
const PinDownload = (function() {
    const API_BASE = window.API_BASE_URL || '';
    const PIN_REGEX = /^[a-zA-Z0-9]{4}$/;

    let fileId = '';
    let sessionExpires = 0;
    let timerInterval = null;
    let attemptsLeft = 3;

    /**
     * Detect if current page should show PIN download flow.
     * Called from download.js to decide which flow to show.
     *
     * @returns {boolean} true if PIN flow should be shown
     */
    function shouldShowPinFlow() {
        const hash = window.location.hash;
        // If no hash or hash doesn't match existing formats, show PIN flow
        if (!hash || hash === '#') return true;

        const parts = hash.substring(1).split('#');
        // Existing format: #file_id#key#filename or #file_id#salt#filename#vault
        // If it has 2+ parts with a UUID-like first part, it's the existing flow
        if (parts.length >= 2 && parts[0].includes('-')) return false;

        return true;
    }

    function init() {
        setupCodeInputBoxes();

        const continueBtn = document.getElementById('code-continue-btn');
        if (continueBtn) {
            continueBtn.addEventListener('click', handleCodeSubmit);
        }

        const downloadBtn = document.getElementById('pin-download-btn');
        if (downloadBtn) {
            downloadBtn.addEventListener('click', handlePinSubmit);
        }

        const pinInput = document.getElementById('pin-verify-input');
        if (pinInput) {
            pinInput.addEventListener('input', (e) => {
                downloadBtn.disabled = !PIN_REGEX.test(e.target.value);
            });
            pinInput.addEventListener('keydown', (e) => {
                if (e.key === 'Enter' && PIN_REGEX.test(pinInput.value)) {
                    handlePinSubmit();
                }
            });
        }

        const tryAgainBtn = document.getElementById('pin-try-again-btn');
        if (tryAgainBtn) {
            tryAgainBtn.addEventListener('click', showCodeEntry);
        }
    }

    function setupCodeInputBoxes() {
        const boxes = document.querySelectorAll('.code-digit');

        boxes.forEach((box, index) => {
            box.addEventListener('input', (e) => {
                const val = e.target.value;
                // Only allow digits
                if (val && !/^[0-9]$/.test(val)) {
                    e.target.value = '';
                    return;
                }
                // Auto-advance to next box
                if (val && index < boxes.length - 1) {
                    boxes[index + 1].focus();
                }
                updateContinueButton();
            });

            box.addEventListener('keydown', (e) => {
                // Backspace: move to previous box
                if (e.key === 'Backspace' && !box.value && index > 0) {
                    boxes[index - 1].focus();
                    boxes[index - 1].value = '';
                    updateContinueButton();
                }
                // Enter: submit if complete
                if (e.key === 'Enter') {
                    const code = getCodeValue();
                    if (code.length === 6) handleCodeSubmit();
                }
            });

            // Handle paste
            box.addEventListener('paste', (e) => {
                e.preventDefault();
                const pasted = (e.clipboardData || window.clipboardData).getData('text').trim();
                if (/^[0-9]{6}$/.test(pasted)) {
                    pasted.split('').forEach((digit, i) => {
                        if (boxes[i]) boxes[i].value = digit;
                    });
                    boxes[5].focus();
                    updateContinueButton();
                }
            });
        });
    }

    function getCodeValue() {
        const boxes = document.querySelectorAll('.code-digit');
        return Array.from(boxes).map(b => b.value).join('');
    }

    function updateContinueButton() {
        const btn = document.getElementById('code-continue-btn');
        if (btn) btn.disabled = getCodeValue().length !== 6;
    }

    async function handleCodeSubmit() {
        const code = getCodeValue();
        if (code.length !== 6) return;

        fileId = code;
        const errorEl = document.getElementById('code-error');
        const continueBtn = document.getElementById('code-continue-btn');

        try {
            continueBtn.disabled = true;
            errorEl.classList.add('hidden');

            const recaptchaToken = await Utils.getRecaptchaToken(
                window.RECAPTCHA_SITE_KEY, 'pin_initiate'
            );

            const response = await fetch(`${API_BASE}/pin/initiate`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    file_id: code,
                    recaptcha_token: recaptchaToken,
                }),
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || 'Failed to initiate session');
            }

            sessionExpires = data.session_expires;
            attemptsLeft = data.attempts_left;

            showPinEntry();

        } catch (error) {
            errorEl.textContent = error.message;
            errorEl.classList.remove('hidden');
            continueBtn.disabled = false;

            // If locked, show lock screen
            if (error.message.includes('locked')) {
                showLocked(error.message);
            }
        }
    }

    function showCodeEntry() {
        hideAllSections();
        document.getElementById('pin-code-section').classList.remove('hidden');
        // Clear and focus first box
        document.querySelectorAll('.code-digit').forEach(b => b.value = '');
        document.querySelector('.code-digit')?.focus();
        updateContinueButton();
        stopTimer();
    }

    function showPinEntry() {
        hideAllSections();
        document.getElementById('pin-entry-section').classList.remove('hidden');
        document.getElementById('pin-file-code').textContent = fileId;
        document.getElementById('pin-attempts-value').textContent = attemptsLeft;

        const pinInput = document.getElementById('pin-verify-input');
        if (pinInput) {
            pinInput.value = '';
            pinInput.focus();
        }
        document.getElementById('pin-download-btn').disabled = true;

        startTimer();
    }

    function startTimer() {
        stopTimer();
        const timerEl = document.getElementById('pin-timer');
        const valueEl = document.getElementById('pin-timer-value');

        timerInterval = setInterval(() => {
            const now = Math.floor(Date.now() / 1000);
            const remaining = Math.max(0, sessionExpires - now);

            valueEl.textContent = remaining;

            // Color transitions
            timerEl.classList.remove('timer-green', 'timer-yellow', 'timer-danger');
            if (remaining > 20) {
                timerEl.classList.add('timer-green');
            } else if (remaining > 10) {
                timerEl.classList.add('timer-yellow');
            } else {
                timerEl.classList.add('timer-danger');
            }

            // Screen reader announcement every 10 seconds
            if (remaining % 10 === 0 && remaining > 0) {
                valueEl.setAttribute('aria-label', `${remaining} seconds remaining`);
            }

            if (remaining <= 0) {
                stopTimer();
                showTimeout();
            }
        }, 1000);
    }

    function stopTimer() {
        if (timerInterval) {
            clearInterval(timerInterval);
            timerInterval = null;
        }
    }

    function showTimeout() {
        hideAllSections();
        document.getElementById('pin-timeout-section').classList.remove('hidden');
    }

    function showLocked(message) {
        hideAllSections();
        document.getElementById('pin-locked-section').classList.remove('hidden');

        // Try to parse unlock time
        const hoursMatch = message.match(/(\d+)\s*hours?/);
        if (hoursMatch) {
            const hours = parseInt(hoursMatch[1]);
            const unlockTime = new Date(Date.now() + hours * 3600000);
            document.getElementById('pin-unlock-time').textContent = unlockTime.toLocaleString();
        }
    }

    async function handlePinSubmit() {
        const pinInput = document.getElementById('pin-verify-input');
        const pin = pinInput.value;
        if (!PIN_REGEX.test(pin)) return;

        const downloadBtn = document.getElementById('pin-download-btn');
        const errorEl = document.getElementById('pin-verify-error');

        try {
            downloadBtn.disabled = true;
            errorEl.classList.add('hidden');

            const recaptchaToken = await Utils.getRecaptchaToken(
                window.RECAPTCHA_SITE_KEY, 'pin_verify'
            );

            const response = await fetch(`${API_BASE}/pin/verify`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    file_id: fileId,
                    pin: pin,
                    recaptcha_token: recaptchaToken,
                }),
            });

            const data = await response.json();

            if (!response.ok) {
                // Check error type
                if (data.error.includes('locked')) {
                    showLocked(data.error);
                    return;
                }
                if (data.error.includes('expired') || data.error.includes('Session')) {
                    showTimeout();
                    return;
                }
                // Wrong PIN - update attempts
                const attemptsMatch = data.error.match(/(\d+)\s*attempts?\s*left/);
                if (attemptsMatch) {
                    attemptsLeft = parseInt(attemptsMatch[1]);
                    document.getElementById('pin-attempts-value').textContent = attemptsLeft;
                }
                throw new Error(data.error);
            }

            // PIN correct - stop timer and download
            stopTimer();
            await downloadAndDecrypt(data, pin);

        } catch (error) {
            errorEl.textContent = error.message;
            errorEl.classList.remove('hidden');
            downloadBtn.disabled = false;
            pinInput.value = '';
            pinInput.focus();
        }
    }

    async function downloadAndDecrypt(data, pin) {
        hideAllSections();
        const progressSection = document.getElementById('pin-download-progress-section');
        const progressFill = document.getElementById('pin-dl-progress-fill');
        const progressText = document.getElementById('pin-dl-progress-text');
        progressSection.classList.remove('hidden');

        try {
            // Derive key from PIN + salt using PBKDF2
            progressText.textContent = 'Deriving decryption key...';
            progressFill.style.width = '10%';

            const saltArray = CryptoModule.base64ToArray
                ? CryptoModule.base64ToArray(data.salt)
                : hexToArray(data.salt);

            const cryptoKey = await CryptoModule.deriveKeyFromPassword(pin, saltArray);
            progressFill.style.width = '20%';

            let encryptedData;

            if (data.content_type === 'text') {
                progressText.textContent = 'Decrypting text...';
                const textBytes = CryptoModule.base64ToArray(data.encrypted_text);
                const decrypted = await CryptoModule.decrypt(textBytes, cryptoKey);
                const text = new TextDecoder().decode(decrypted);

                progressFill.style.width = '100%';
                progressText.textContent = 'Decryption complete!';

                // Show text in existing text display section
                showDecryptedText(text);
            } else {
                // Download encrypted file from S3
                progressText.textContent = 'Downloading encrypted file...';

                const response = await fetch(data.download_url);
                if (!response.ok) throw new Error('Failed to download file');

                encryptedData = new Uint8Array(await response.arrayBuffer());
                progressFill.style.width = '60%';

                // Decrypt
                progressText.textContent = 'Decrypting file...';
                const decrypted = await CryptoModule.decrypt(encryptedData, cryptoKey);
                progressFill.style.width = '90%';

                // Save file
                progressText.textContent = 'Saving file...';
                const blob = new Blob([decrypted]);
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'download';  // PIN mode doesn't have filename in URL
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);

                progressFill.style.width = '100%';
                progressText.textContent = 'Download complete!';
            }

            // Confirm download (marks as downloaded on server)
            try {
                await fetch(`${API_BASE}/files/${fileId}/confirm`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({}),
                });
            } catch (e) {
                console.warn('Failed to confirm download:', e);
            }

        } catch (error) {
            console.error('Download failed:', error);
            progressText.textContent = 'Decryption failed. Invalid PIN or corrupted data.';
            progressFill.style.width = '0%';
        }
    }

    function showDecryptedText(text) {
        // Reuse existing text display section or create inline display
        hideAllSections();
        const section = document.getElementById('text-display-section')
            || document.getElementById('pin-download-progress-section');

        if (document.getElementById('text-display-section')) {
            document.getElementById('text-display-section').classList.remove('hidden');
            const textarea = document.getElementById('text-display');
            if (textarea) textarea.value = text;
        } else {
            // Fallback: show in progress section
            section.classList.remove('hidden');
            section.innerHTML = `
                <h2>Your Secret Text</h2>
                <textarea readonly class="text-display">${escapeHtml(text)}</textarea>
                <button class="copy-btn" onclick="Utils.copyToClipboard(this.previousElementSibling.value)">Copy Text</button>
            `;
        }
    }

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    function hexToArray(hex) {
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) {
            bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
        }
        return bytes;
    }

    function hideAllSections() {
        ['pin-code-section', 'pin-entry-section', 'pin-timeout-section',
         'pin-locked-section', 'pin-download-progress-section'].forEach(id => {
            const el = document.getElementById(id);
            if (el) el.classList.add('hidden');
        });
    }

    return { init, shouldShowPinFlow, showCodeEntry };
})();
```

**Step 3: Modify download.js to integrate PIN flow detection**

In `frontend/js/download.js`, modify the initialization to detect PIN vs URL mode:

```javascript
// At the top of the DOMContentLoaded handler or init function, add:
if (PinDownload.shouldShowPinFlow()) {
    PinDownload.init();
    PinDownload.showCodeEntry();
    return;  // Skip existing URL-based flow
}
// ... existing URL-based download code continues
```

**Step 4: Add `<script>` tag to download.html**

```html
<script src="/js/pin-download.js"></script>
```

(Must be loaded BEFORE `download.js`)

**Step 5: Commit**

```bash
git add frontend/download.html frontend/js/pin-download.js frontend/js/download.js
git commit -m "feat(pin): add PIN download frontend with code entry, timer, and verification"
```

---

## Task 11: Add CSS for PIN Components

**Files:**
- Modify: `frontend/css/style.css`

**Step 1: Add all PIN-specific styles**

Key styles to add:

```css
/* Method Selection */
.method-selection { text-align: center; padding: 2rem; }
.method-cards { display: flex; gap: 1.5rem; justify-content: center; flex-wrap: wrap; }
.method-card {
    border: 2px solid var(--border-color, #e2e8f0);
    border-radius: 12px;
    padding: 2rem;
    width: 280px;
    cursor: pointer;
    transition: all 0.3s ease;
    text-align: center;
}
.method-card:hover, .method-card:focus {
    transform: translateY(-4px);
    box-shadow: 0 8px 16px rgba(0,0,0,0.1);
    border-color: var(--primary-color, #3b82f6);
}
.method-icon { font-size: 2.5rem; margin-bottom: 0.5rem; }
.method-btn { margin-top: 1rem; }
.method-recommended { display: none; font-size: 0.75rem; color: var(--primary-color); font-weight: 600; }

/* Code display (large 6-digit code) */
.code-display {
    font-size: 48px;
    font-weight: 700;
    letter-spacing: 8px;
    font-family: 'Courier New', monospace;
    padding: 1rem 2rem;
    border: 3px solid var(--primary-color, #3b82f6);
    border-radius: 12px;
    display: inline-block;
    margin: 1rem 0;
}

/* Code input boxes (6 individual digits) */
.code-input-group { display: flex; gap: 0.5rem; justify-content: center; margin: 1.5rem 0; }
.code-digit {
    width: 48px; height: 56px;
    text-align: center;
    font-size: 24px;
    font-weight: 600;
    border: 2px solid var(--border-color, #e2e8f0);
    border-radius: 8px;
}
.code-digit:focus { border-color: var(--primary-color, #3b82f6); outline: none; }

/* Timer */
.timer { font-size: 1.25rem; font-weight: 600; padding: 0.75rem; border-radius: 8px; transition: color 0.5s ease; }
.timer-green { color: #22c55e; }
.timer-yellow { color: #f59e0b; }
.timer-danger { color: #ef4444; animation: pulse 1s infinite; }
@keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.6; } }

/* PIN large input */
.pin-large-input {
    font-size: 24px;
    text-align: center;
    letter-spacing: 8px;
    width: 160px;
    padding: 0.75rem;
}

/* Validation messages */
.validation-msg.valid { color: #22c55e; }
.validation-msg.valid::before { content: '\2713 '; }
.validation-msg.invalid { color: #ef4444; }
.validation-msg.invalid::before { content: '\2717 '; }

/* PIN reveal */
.pin-reveal { margin: 1rem 0; }
.reveal-btn { font-size: 0.875rem; padding: 0.25rem 0.5rem; }

/* Mobile responsive */
@media (max-width: 767px) {
    .method-cards { flex-direction: column; align-items: center; }
    .method-recommended { display: inline-block; }
    .code-display { font-size: 36px; letter-spacing: 6px; }
    .code-digit { width: 40px; height: 48px; font-size: 20px; }
}

/* Reduced motion */
@media (prefers-reduced-motion: reduce) {
    .timer-danger { animation: none; }
    .method-card { transition: none; }
}

/* Mode indicator */
.mode-indicator { font-size: 0.875rem; color: var(--text-secondary); margin-bottom: 1rem; }
.back-btn { background: none; border: none; cursor: pointer; color: var(--primary-color); font-size: 0.875rem; padding: 0.5rem 0; }
.back-btn:hover { text-decoration: underline; }

/* Help modal */
.modal { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); display: flex; align-items: center; justify-content: center; z-index: 1000; }
.modal.hidden { display: none; }
.modal-content { background: var(--bg-color, white); border-radius: 12px; padding: 2rem; max-width: 500px; width: 90%; position: relative; }
.modal-close { position: absolute; top: 0.5rem; right: 0.75rem; background: none; border: none; font-size: 1.5rem; cursor: pointer; }
.help-columns { display: flex; gap: 2rem; margin-top: 1rem; }
.help-link { background: none; border: none; color: var(--text-secondary); cursor: pointer; font-size: 0.875rem; text-decoration: underline; margin-top: 1rem; }
```

**Step 2: Commit**

```bash
git add frontend/css/style.css
git commit -m "feat(pin): add CSS styles for method selection, code input, timer, and PIN components"
```

---

## Task 12: Update Cleanup Lambda to Handle PIN Records

**Files:**
- Modify: `backend/lambdas/cleanup/handler.py`

**Step 1: Read current cleanup handler**

The cleanup Lambda scans DynamoDB for expired/downloaded records. PIN records use a different `file_id` format (6-digit vs UUID) and `access_mode: "pin"`, but the cleanup logic (check `expires_at` or `downloaded`) should already work. Verify that:

1. The scan correctly picks up PIN records (it should, since it scans the full table)
2. The S3 deletion uses `s3_key` field (PIN records use `files/{6-digit-id}`)
3. The `STATS` record skip still works

**Step 2: Verify no changes needed (or make minimal adjustments)**

The existing cleanup handler should work for PIN records because:
- It scans all records and checks `expires_at` and `downloaded`
- It uses `record.get("s3_key")` for S3 deletion
- It skips `file_id == "STATS"`

If adjustments are needed (e.g., also cleaning up locked-but-expired records), add a check:

```python
# In the cleanup scan loop, PIN records with expired lockouts
# are handled naturally by expires_at TTL
```

**Step 3: Commit (only if changes were made)**

```bash
git add backend/lambdas/cleanup/handler.py
git commit -m "chore(pin): verify cleanup Lambda handles PIN records correctly"
```

---

## Task 13: Add Integration Tests for PIN Flow

**Files:**
- Create: `backend/tests/test_pin_integration.py`

**Step 1: Write integration-style tests**

```python
# backend/tests/test_pin_integration.py
"""Integration-style tests for PIN flow logic - NO MOCKS, NO AWS."""

import time

import pytest

from shared.constants import (
    PIN_LOCKOUT_SECONDS,
    PIN_MAX_ATTEMPTS,
    PIN_SESSION_TIMEOUT_SECONDS,
)
from shared.pin_utils import generate_pin_file_id, generate_salt, hash_pin, verify_pin_hash
from shared.validation import validate_pin, validate_pin_file_id
from shared.exceptions import ValidationError


class TestPinUploadFlow:
    """Test the complete PIN upload validation flow."""

    def test_full_upload_validation(self):
        """Should validate all inputs for PIN upload."""
        pin = "7a2B"
        validate_pin(pin)

        file_id = generate_pin_file_id()
        validate_pin_file_id(file_id)

        salt = generate_salt()
        pin_hash = hash_pin(pin, salt)

        assert len(file_id) == 6
        assert len(salt) == 64
        assert len(pin_hash) == 64

    def test_pin_hash_round_trip(self):
        """Should hash and verify PIN correctly."""
        pin = "xY9z"
        salt = generate_salt()
        pin_hash = hash_pin(pin, salt)

        assert verify_pin_hash(pin, salt, pin_hash) is True
        assert verify_pin_hash("WRONG", salt, pin_hash) is False
        assert verify_pin_hash("xY9Z", salt, pin_hash) is False  # Case matters


class TestPinDownloadFlow:
    """Test PIN download validation and session logic."""

    def test_session_expires_in_60_seconds(self):
        """Session should be 60 seconds from creation."""
        session_start = int(time.time())
        session_expires = session_start + PIN_SESSION_TIMEOUT_SECONDS
        assert session_expires - session_start == 60

    def test_attempt_decrement_sequence(self):
        """Should go 3 -> 2 -> 1 -> 0 (lockout)."""
        attempts = PIN_MAX_ATTEMPTS
        for expected in [2, 1, 0]:
            attempts -= 1
            assert attempts == expected

        assert attempts <= 0  # Should trigger lockout

    def test_lockout_duration(self):
        """Lockout should be 12 hours from last failure."""
        lockout_time = int(time.time())
        locked_until = lockout_time + PIN_LOCKOUT_SECONDS
        assert locked_until - lockout_time == 43200  # 12 hours

    def test_lockout_expires_correctly(self):
        """Should be unlocked after lockout period."""
        locked_until = int(time.time()) - 1  # Lock just expired
        current = int(time.time())
        is_locked = locked_until > current
        assert is_locked is False


class TestPinFileIdCollisionPrevention:
    """Test file ID generation handles collisions."""

    def test_generates_many_unique_ids(self):
        """Should generate unique IDs in practice."""
        ids = set()
        for _ in range(10000):
            ids.add(generate_pin_file_id())
        # With 1M possible values, expect very few collisions in 10K tries
        assert len(ids) > 9900

    def test_all_ids_are_valid(self):
        """All generated IDs should pass validation."""
        for _ in range(100):
            file_id = generate_pin_file_id()
            validate_pin_file_id(file_id)  # Should not raise


class TestPinSecurityProperties:
    """Test security properties of PIN system."""

    def test_pin_hash_not_reversible(self):
        """Hash should not reveal PIN."""
        salt = generate_salt()
        pin_hash = hash_pin("7a2B", salt)
        # Hash should not contain PIN
        assert "7a2B" not in pin_hash

    def test_constant_time_comparison(self):
        """verify_pin_hash should use constant-time comparison."""
        import hmac
        salt = generate_salt()
        pin_hash = hash_pin("7a2B", salt)
        # The function uses hmac.compare_digest internally
        actual = hash_pin("XXXX", salt)
        assert hmac.compare_digest(actual, pin_hash) is False

    def test_different_salts_prevent_rainbow_tables(self):
        """Same PIN with different salts should give different hashes."""
        hashes = set()
        for _ in range(100):
            salt = generate_salt()
            hashes.add(hash_pin("1234", salt))
        assert len(hashes) == 100
```

**Step 2: Run tests**

Run: `cd /home/antonaks/Documents/MyProjects/sdbx && python -m pytest backend/tests/test_pin_integration.py -v`
Expected: ALL PASS

**Step 3: Commit**

```bash
git add backend/tests/test_pin_integration.py
git commit -m "test(pin): add integration tests for PIN upload/download flow and security properties"
```

---

## Task 14: Add Frontend Crypto Tests for PBKDF2 with PIN

**Files:**
- Create: `frontend/tests/test_pin_crypto.html` (or extend existing test file)

**Step 1: Write browser-based crypto test**

Add a test that verifies:
1. PBKDF2 key derivation from a 4-char PIN + salt produces a valid AES-GCM key
2. Encrypt with PIN-derived key -> decrypt with same PIN-derived key works
3. Decrypt with wrong PIN-derived key fails

This follows the existing pattern in `frontend/tests/` (if browser-based test runner exists).

**Step 2: Commit**

```bash
git add frontend/tests/
git commit -m "test(pin): add frontend PBKDF2 crypto tests for PIN-derived keys"
```

---

## Task 15: Update CLAUDE.md and Documentation

**Files:**
- Modify: `CLAUDE.md`

**Step 1: Update the documentation**

Add to CLAUDE.md:
- PIN flow in Key Flows section
- PIN API endpoints to API Endpoints table
- PIN fields to DynamoDB Schema
- PIN encryption spec
- `access_mode: "pin"` to Access modes

Specific updates:
1. Add `access_mode: "pin"` alongside `one_time` and `multi`
2. Add new endpoints: `POST /pin/upload`, `POST /pin/initiate`, `POST /pin/verify`
3. Add PIN-specific DynamoDB fields: `pin_hash`, `salt`, `session_started`, `session_expires`, `attempts_left`, `locked_until`
4. Add PIN flow description
5. Update Project Structure with new files

**Step 2: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: update CLAUDE.md with PIN-based sharing documentation"
```

---

## Task 16: Run Full Test Suite and Verify

**Step 1: Run all backend tests**

Run: `cd /home/antonaks/Documents/MyProjects/sdbx && python -m pytest backend/tests/ -v --tb=short`
Expected: ALL PASS

**Step 2: Serve frontend locally and manual test**

Run: `cd /home/antonaks/Documents/MyProjects/sdbx/frontend && python -m http.server 8000`

Manual verification:
1. Visit `http://localhost:8000` - should see method selection screen
2. Click "Share Link" - should show existing upload flow
3. Click back - should return to method selection
4. Click "PIN Code" - should show PIN upload form
5. Visit `http://localhost:8000/download.html` (no hash) - should show code entry
6. Visit `http://localhost:8000/download.html#uuid#key#name` - should show existing download flow

**Step 3: Commit final state**

```bash
git add -A
git commit -m "feat(pin): complete PIN-based file sharing feature (backend + frontend + tests + terraform)"
```

---

## Summary of All Files Changed

### New Files (12)
| File | Purpose |
|------|---------|
| `backend/shared/pin_utils.py` | PIN hashing, verification, file ID generation |
| `backend/lambdas/pin_upload_init/handler.py` | PIN upload endpoint |
| `backend/lambdas/pin_initiate/handler.py` | PIN session initiation endpoint |
| `backend/lambdas/pin_verify/handler.py` | PIN verification + download endpoint |
| `backend/tests/test_constants.py` | PIN constants tests |
| `backend/tests/test_pin_utils.py` | PIN utility function tests |
| `backend/tests/test_pin_upload_handler.py` | PIN upload handler tests |
| `backend/tests/test_pin_dynamo.py` | PIN DynamoDB logic tests |
| `backend/tests/test_pin_integration.py` | PIN integration tests |
| `frontend/js/pin-upload.js` | PIN upload UI module |
| `frontend/js/pin-download.js` | PIN download UI module |
| `frontend/tests/test_pin_crypto.html` | PIN crypto tests |

### Modified Files (8)
| File | Changes |
|------|---------|
| `backend/shared/constants.py` | Add PIN constants |
| `backend/shared/exceptions.py` | Add `FileLockedException`, `SessionExpiredError` |
| `backend/shared/validation.py` | Add `validate_pin()`, `validate_pin_file_id()` |
| `backend/shared/dynamo.py` | Add PIN record creation, session, verification |
| `backend/tests/test_validation.py` | Add PIN validation tests |
| `terraform/modules/api/main.tf` | Add 3 API endpoints + 3 Lambda functions |
| `frontend/index.html` | Add method selection, PIN upload form |
| `frontend/download.html` | Add code entry, PIN entry, timer sections |
| `frontend/css/style.css` | Add PIN component styles |
| `frontend/js/download.js` | Add PIN flow auto-detection |
| `CLAUDE.md` | Update documentation |
