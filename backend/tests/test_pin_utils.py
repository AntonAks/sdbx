"""Unit tests for PIN utility functions - NO MOCKS."""

import pytest
from shared.pin_utils import generate_pin_file_id, generate_salt, hash_pin, verify_pin_hash


class TestGenerateSalt:
    def test_salt_length(self):
        salt = generate_salt()
        assert len(salt) == 64  # 32 bytes = 64 hex chars

    def test_salt_is_hex(self):
        salt = generate_salt()
        int(salt, 16)

    def test_salt_is_unique(self):
        salts = {generate_salt() for _ in range(100)}
        assert len(salts) == 100


class TestHashPin:
    def test_hash_is_sha256(self):
        salt = generate_salt()
        pin_hash = hash_pin("7a2B", salt)
        assert len(pin_hash) == 64

    def test_hash_is_deterministic(self):
        salt = generate_salt()
        assert hash_pin("7a2B", salt) == hash_pin("7a2B", salt)

    def test_different_pins_different_hashes(self):
        salt = generate_salt()
        assert hash_pin("7a2B", salt) != hash_pin("9x4Y", salt)

    def test_different_salts_different_hashes(self):
        salt1, salt2 = generate_salt(), generate_salt()
        assert hash_pin("7a2B", salt1) != hash_pin("7a2B", salt2)

    def test_case_sensitive(self):
        salt = generate_salt()
        assert hash_pin("abcd", salt) != hash_pin("ABCD", salt)


class TestVerifyPinHash:
    def test_correct_pin_verifies(self):
        salt = generate_salt()
        pin_hash = hash_pin("7a2B", salt)
        assert verify_pin_hash("7a2B", salt, pin_hash) is True

    def test_wrong_pin_fails(self):
        salt = generate_salt()
        pin_hash = hash_pin("7a2B", salt)
        assert verify_pin_hash("XXXX", salt, pin_hash) is False

    def test_case_sensitive_verification(self):
        salt = generate_salt()
        pin_hash = hash_pin("7a2B", salt)
        assert verify_pin_hash("7A2B", salt, pin_hash) is False

    def test_wrong_salt_fails(self):
        salt1, salt2 = generate_salt(), generate_salt()
        pin_hash = hash_pin("7a2B", salt1)
        assert verify_pin_hash("7a2B", salt2, pin_hash) is False


class TestGeneratePinFileId:
    def test_format_six_digits(self):
        file_id = generate_pin_file_id()
        assert len(file_id) == 6
        assert file_id.isdigit()

    def test_zero_padded(self):
        for _ in range(100):
            assert len(generate_pin_file_id()) == 6

    def test_uniqueness(self):
        ids = {generate_pin_file_id() for _ in range(1000)}
        assert len(ids) >= 990

    def test_range(self):
        for _ in range(100):
            file_id = generate_pin_file_id()
            assert 0 <= int(file_id) <= 999999
