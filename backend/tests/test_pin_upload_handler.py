"""Unit tests for PIN upload init handler - validation and response format."""

import pytest

from shared.exceptions import ValidationError
from shared.pin_utils import generate_pin_file_id, generate_salt, hash_pin, verify_pin_hash
from shared.validation import validate_pin


class TestPinUploadInitValidation:
    """Tests for PIN validation used by pin_upload_init handler."""

    def test_pin_validation_rejects_short_pin(self):
        """Should reject PIN shorter than 4 characters."""
        with pytest.raises(ValidationError):
            validate_pin("12")

    def test_pin_validation_rejects_long_pin(self):
        """Should reject PIN longer than 4 characters."""
        with pytest.raises(ValidationError):
            validate_pin("12345")

    def test_pin_validation_rejects_special_chars(self):
        """Should reject PIN with special characters."""
        with pytest.raises(ValidationError):
            validate_pin("12@#")

    def test_pin_validation_rejects_empty(self):
        """Should reject empty PIN."""
        with pytest.raises(ValidationError):
            validate_pin("")

    def test_pin_validation_rejects_none(self):
        """Should reject None PIN."""
        with pytest.raises(ValidationError):
            validate_pin(None)

    def test_pin_validation_accepts_alphanumeric(self):
        """Should accept valid 4-character alphanumeric PIN."""
        validate_pin("7a2B")

    def test_pin_validation_accepts_all_digits(self):
        """Should accept all-digit PIN."""
        validate_pin("1234")

    def test_pin_validation_accepts_all_letters(self):
        """Should accept all-letter PIN."""
        validate_pin("aBcD")


class TestPinFileIdGeneration:
    """Tests for 6-digit file ID generation."""

    def test_file_id_is_six_digits(self):
        """Should generate exactly 6-digit string."""
        file_id = generate_pin_file_id()
        assert len(file_id) == 6
        assert file_id.isdigit()

    def test_file_id_is_zero_padded(self):
        """Should be zero-padded (always 6 chars even for small numbers)."""
        # Generate many IDs to increase chance of hitting small numbers
        ids = [generate_pin_file_id() for _ in range(100)]
        for fid in ids:
            assert len(fid) == 6
            assert fid.isdigit()

    def test_file_id_uniqueness(self):
        """Should generate different IDs across multiple calls (probabilistic)."""
        ids = {generate_pin_file_id() for _ in range(50)}
        # With 1M possible IDs, 50 samples should almost always be unique
        assert len(ids) > 1


class TestPinSaltAndHash:
    """Tests for PIN salt generation and hash verification."""

    def test_salt_generation_returns_hex_string(self):
        """Should return 64-char hex string (32 bytes)."""
        salt = generate_salt()
        assert len(salt) == 64
        assert all(c in "0123456789abcdef" for c in salt)

    def test_salt_is_random(self):
        """Should generate different salts each time."""
        salts = {generate_salt() for _ in range(10)}
        assert len(salts) == 10

    def test_hash_pin_returns_hex_string(self):
        """Should return 64-char hex hash."""
        salt = generate_salt()
        pin_hash = hash_pin("7a2B", salt)
        assert len(pin_hash) == 64
        assert all(c in "0123456789abcdef" for c in pin_hash)

    def test_hash_pin_deterministic(self):
        """Same PIN + salt should produce same hash."""
        salt = generate_salt()
        hash1 = hash_pin("7a2B", salt)
        hash2 = hash_pin("7a2B", salt)
        assert hash1 == hash2

    def test_hash_pin_different_salts(self):
        """Same PIN with different salts should produce different hashes."""
        salt1 = generate_salt()
        salt2 = generate_salt()
        hash1 = hash_pin("7a2B", salt1)
        hash2 = hash_pin("7a2B", salt2)
        assert hash1 != hash2

    def test_verify_pin_hash_correct(self):
        """Should verify correct PIN against stored hash."""
        salt = generate_salt()
        pin_hash = hash_pin("7a2B", salt)
        assert verify_pin_hash("7a2B", salt, pin_hash) is True

    def test_verify_pin_hash_incorrect(self):
        """Should reject incorrect PIN."""
        salt = generate_salt()
        pin_hash = hash_pin("7a2B", salt)
        assert verify_pin_hash("XXXX", salt, pin_hash) is False

    def test_verify_pin_hash_wrong_salt(self):
        """Should reject correct PIN with wrong salt."""
        salt1 = generate_salt()
        salt2 = generate_salt()
        pin_hash = hash_pin("7a2B", salt1)
        assert verify_pin_hash("7a2B", salt2, pin_hash) is False
