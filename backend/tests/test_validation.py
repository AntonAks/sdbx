"""Unit tests for validation module - NO MOCKS."""

import pytest
from shared.validation import validate_file_id, validate_file_size, validate_ttl
from shared.exceptions import ValidationError


class TestValidateFileId:
    """Test file ID validation (UUID v4 format)."""

    def test_valid_uuid_v4(self):
        """Should accept valid UUID v4."""
        # Valid UUID v4 examples
        valid_ids = [
            "550e8400-e29b-41d4-a716-446655440000",
            "6ba7b810-9dad-41d1-80b4-00c04fd430c8",
            "f47ac10b-58cc-4372-a567-0e02b2c3d479",
        ]

        for file_id in valid_ids:
            validate_file_id(file_id)  # Should not raise

    def test_valid_uuid_v4_uppercase(self):
        """Should accept uppercase UUID v4."""
        validate_file_id("550E8400-E29B-41D4-A716-446655440000")

    def test_valid_uuid_v4_mixed_case(self):
        """Should accept mixed case UUID v4."""
        validate_file_id("550e8400-E29B-41d4-A716-446655440000")

    def test_none_file_id(self):
        """Should reject None."""
        with pytest.raises(ValidationError, match="File ID is required"):
            validate_file_id(None)

    def test_empty_string(self):
        """Should reject empty string."""
        with pytest.raises(ValidationError, match="File ID is required"):
            validate_file_id("")

    def test_invalid_format(self):
        """Should reject non-UUID format."""
        invalid_ids = [
            "not-a-uuid",
            "12345678",
            "550e8400-e29b-41d4-a716",  # Too short
            "550e8400-e29b-41d4-a716-446655440000-extra",  # Too long
            "550e8400_e29b_41d4_a716_446655440000",  # Wrong separator
        ]

        for file_id in invalid_ids:
            with pytest.raises(ValidationError, match="Invalid file ID format"):
                validate_file_id(file_id)

    def test_uuid_v1_rejected(self):
        """Should reject UUID v1 (not v4)."""
        # UUID v1 has different version bits
        with pytest.raises(ValidationError, match="Invalid file ID format"):
            validate_file_id("550e8400-e29b-11d4-a716-446655440000")

    def test_uuid_v3_rejected(self):
        """Should reject UUID v3 (not v4)."""
        with pytest.raises(ValidationError, match="Invalid file ID format"):
            validate_file_id("550e8400-e29b-31d4-a716-446655440000")

    def test_no_sensitive_info_in_error(self):
        """Should not expose file_id in error message."""
        malicious_id = "<script>alert('xss')</script>"

        try:
            validate_file_id(malicious_id)
            assert False, "Should have raised ValidationError"
        except ValidationError as e:
            # Error message should NOT contain the actual ID
            assert malicious_id not in str(e)
            assert "Invalid file ID format" in str(e)


class TestValidateFileSize:
    """Test file size validation."""

    def test_valid_small_file(self):
        """Should accept small file sizes."""
        validate_file_size(1024)  # 1 KB
        validate_file_size(1024 * 1024)  # 1 MB

    def test_valid_max_file(self):
        """Should accept exactly 500 MB."""
        validate_file_size(500 * 1024 * 1024)  # Exactly 500 MB

    def test_valid_near_max_file(self):
        """Should accept file just under limit."""
        validate_file_size(500 * 1024 * 1024 - 1)  # 500 MB - 1 byte

    def test_reject_zero(self):
        """Should reject zero size."""
        with pytest.raises(ValidationError, match="must be positive"):
            validate_file_size(0)

    def test_reject_negative(self):
        """Should reject negative size."""
        with pytest.raises(ValidationError, match="must be positive"):
            validate_file_size(-1)

    def test_reject_negative_large(self):
        """Should reject large negative size."""
        with pytest.raises(ValidationError, match="must be positive"):
            validate_file_size(-1000000)

    def test_reject_too_large(self):
        """Should reject file over 500 MB."""
        with pytest.raises(ValidationError, match="exceeds maximum limit"):
            validate_file_size(500 * 1024 * 1024 + 1)

    def test_reject_way_too_large(self):
        """Should reject very large file."""
        with pytest.raises(ValidationError, match="exceeds maximum limit"):
            validate_file_size(1024 * 1024 * 1024)  # 1 GB

    def test_reject_non_integer(self):
        """Should reject non-integer types."""
        with pytest.raises(ValidationError, match="must be an integer"):
            validate_file_size("1024")

        with pytest.raises(ValidationError, match="must be an integer"):
            validate_file_size(1024.5)

        with pytest.raises(ValidationError, match="must be an integer"):
            validate_file_size(None)

    def test_no_sensitive_info_in_error(self):
        """Should not expose exact file size in error message."""
        huge_size = 999999999999

        try:
            validate_file_size(huge_size)
            assert False, "Should have raised ValidationError"
        except ValidationError as e:
            # Error message should NOT contain the actual size
            assert str(huge_size) not in str(e)
            assert "500 MB" in str(e)  # Generic limit is OK


class TestValidateTTL:
    """Test TTL validation."""

    def test_valid_1h(self):
        """Should accept '1h'."""
        validate_ttl("1h")

    def test_valid_12h(self):
        """Should accept '12h'."""
        validate_ttl("12h")

    def test_valid_24h(self):
        """Should accept '24h'."""
        validate_ttl("24h")

    def test_reject_invalid_format(self):
        """Should reject invalid TTL formats."""
        invalid_ttls = [
            "1",
            "1hour",
            "1 hour",
            "2h",
            "6h",
            "48h",
            "1d",
            "1H",  # Case sensitive
            "12H",
            "",
            None,
        ]

        for ttl in invalid_ttls:
            with pytest.raises(ValidationError, match="TTL must be one of"):
                validate_ttl(ttl)

    def test_error_message_shows_allowed_values(self):
        """Should show allowed values in error message."""
        try:
            validate_ttl("invalid")
            assert False, "Should have raised ValidationError"
        except ValidationError as e:
            error_msg = str(e)
            assert "1h" in error_msg
            assert "12h" in error_msg
            assert "24h" in error_msg


class TestValidationEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_file_size_boundary_minus_one(self):
        """Test exact boundary - 1."""
        max_size = 500 * 1024 * 1024
        validate_file_size(max_size - 1)  # Should pass

    def test_file_size_boundary_plus_one(self):
        """Test exact boundary + 1."""
        max_size = 500 * 1024 * 1024
        with pytest.raises(ValidationError):
            validate_file_size(max_size + 1)  # Should fail

    def test_file_size_minimum_valid(self):
        """Test minimum valid file size."""
        validate_file_size(1)  # 1 byte should be valid

    def test_uuid_all_zeros(self):
        """Test UUID with all zeros (valid format but unusual)."""
        # Valid UUID v4 format with all zeros (version and variant bits set correctly)
        validate_file_id("00000000-0000-4000-8000-000000000000")

    def test_uuid_all_fs(self):
        """Test UUID with all Fs (valid format but unusual)."""
        # Valid UUID v4 format with all Fs (version and variant bits set correctly)
        validate_file_id("ffffffff-ffff-4fff-bfff-ffffffffffff")
