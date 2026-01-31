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
