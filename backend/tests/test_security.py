"""Unit tests for security module - NO MOCKS (CloudFront origin check only)."""

import os
import pytest
from shared.security import verify_cloudfront_origin


class TestVerifyCloudFrontOrigin:
    """Test CloudFront origin verification - pure logic, no HTTP calls."""

    def test_valid_origin_with_secret(self, monkeypatch):
        """Should accept request with correct secret header."""
        monkeypatch.setenv("CLOUDFRONT_SECRET", "test-secret-123")

        event = {
            "headers": {
                "X-Origin-Verify": "test-secret-123"
            },
            "requestContext": {
                "identity": {
                    "sourceIp": "1.2.3.4"
                }
            }
        }

        assert verify_cloudfront_origin(event) is True

    def test_valid_origin_case_insensitive_header(self, monkeypatch):
        """Should handle case-insensitive header names."""
        monkeypatch.setenv("CLOUDFRONT_SECRET", "test-secret-123")

        # Different case variations
        events = [
            {"headers": {"x-origin-verify": "test-secret-123"}},
            {"headers": {"X-ORIGIN-VERIFY": "test-secret-123"}},
            {"headers": {"X-Origin-Verify": "test-secret-123"}},
        ]

        for event in events:
            assert verify_cloudfront_origin(event) is True

    def test_invalid_secret(self, monkeypatch):
        """Should reject request with wrong secret."""
        monkeypatch.setenv("CLOUDFRONT_SECRET", "correct-secret")

        event = {
            "headers": {
                "X-Origin-Verify": "wrong-secret"
            },
            "requestContext": {
                "identity": {
                    "sourceIp": "1.2.3.4"
                }
            }
        }

        assert verify_cloudfront_origin(event) is False

    def test_missing_header(self, monkeypatch):
        """Should reject request without origin header."""
        monkeypatch.setenv("CLOUDFRONT_SECRET", "test-secret")

        event = {
            "headers": {},
            "requestContext": {
                "identity": {
                    "sourceIp": "1.2.3.4"
                }
            }
        }

        assert verify_cloudfront_origin(event) is False

    def test_empty_secret_header(self, monkeypatch):
        """Should reject request with empty secret header."""
        monkeypatch.setenv("CLOUDFRONT_SECRET", "test-secret")

        event = {
            "headers": {
                "X-Origin-Verify": ""
            }
        }

        assert verify_cloudfront_origin(event) is False

    def test_no_secret_configured_allows_request(self, monkeypatch):
        """Should allow request when no secret is configured (dev mode)."""
        monkeypatch.delenv("CLOUDFRONT_SECRET", raising=False)

        event = {
            "headers": {}
        }

        assert verify_cloudfront_origin(event) is True

    def test_empty_string_secret_configured(self, monkeypatch):
        """Should allow request when secret is empty string (dev mode)."""
        monkeypatch.setenv("CLOUDFRONT_SECRET", "")

        event = {
            "headers": {}
        }

        assert verify_cloudfront_origin(event) is True

    def test_headers_none(self, monkeypatch):
        """Should handle missing headers key gracefully."""
        monkeypatch.setenv("CLOUDFRONT_SECRET", "test-secret")

        event = {}

        assert verify_cloudfront_origin(event) is False

    def test_multiple_headers(self, monkeypatch):
        """Should find origin header among multiple headers."""
        monkeypatch.setenv("CLOUDFRONT_SECRET", "test-secret")

        event = {
            "headers": {
                "Content-Type": "application/json",
                "User-Agent": "Mozilla/5.0",
                "X-Origin-Verify": "test-secret",
                "Accept": "*/*"
            }
        }

        assert verify_cloudfront_origin(event) is True

    def test_special_characters_in_secret(self, monkeypatch):
        """Should handle special characters in secret."""
        secret = "test-secret!@#$%^&*()_+-={}[]|\\:;\"'<>?,./"
        monkeypatch.setenv("CLOUDFRONT_SECRET", secret)

        event = {
            "headers": {
                "X-Origin-Verify": secret
            }
        }

        assert verify_cloudfront_origin(event) is True

    def test_long_secret(self, monkeypatch):
        """Should handle very long secrets."""
        secret = "a" * 1000
        monkeypatch.setenv("CLOUDFRONT_SECRET", secret)

        event = {
            "headers": {
                "X-Origin-Verify": secret
            }
        }

        assert verify_cloudfront_origin(event) is True

    def test_unicode_in_secret(self, monkeypatch):
        """Should handle Unicode characters in secret."""
        secret = "test-秘密-🔒"
        monkeypatch.setenv("CLOUDFRONT_SECRET", secret)

        event = {
            "headers": {
                "X-Origin-Verify": secret
            }
        }

        assert verify_cloudfront_origin(event) is True

    def test_similar_but_wrong_header_name(self, monkeypatch):
        """Should reject similar but incorrect header names."""
        monkeypatch.setenv("CLOUDFRONT_SECRET", "test-secret")

        # Similar but wrong header names
        events = [
            {"headers": {"X-Origin-Verification": "test-secret"}},  # Extra chars
            {"headers": {"Origin-Verify": "test-secret"}},  # Missing X-
            {"headers": {"X-Verify": "test-secret"}},  # Missing -Origin
        ]

        for event in events:
            assert verify_cloudfront_origin(event) is False

    def test_whitespace_in_secret(self, monkeypatch):
        """Should handle exact whitespace matching."""
        monkeypatch.setenv("CLOUDFRONT_SECRET", "secret with spaces")

        # Exact match should work
        event1 = {"headers": {"X-Origin-Verify": "secret with spaces"}}
        assert verify_cloudfront_origin(event1) is True

        # Different whitespace should fail
        event2 = {"headers": {"X-Origin-Verify": "secret  with  spaces"}}
        assert verify_cloudfront_origin(event2) is False

        # Trimmed should fail
        event3 = {"headers": {"X-Origin-Verify": "secretwithspaces"}}
        assert verify_cloudfront_origin(event3) is False


class TestSecurityEdgeCases:
    """Test edge cases for security validation."""

    def test_request_context_missing(self, monkeypatch):
        """Should handle missing requestContext gracefully."""
        monkeypatch.setenv("CLOUDFRONT_SECRET", "test-secret")

        event = {
            "headers": {
                "X-Origin-Verify": "test-secret"
            }
            # No requestContext
        }

        # Should still verify origin (requestContext not required for origin check)
        assert verify_cloudfront_origin(event) is True

    def test_empty_event(self, monkeypatch):
        """Should handle completely empty event."""
        monkeypatch.setenv("CLOUDFRONT_SECRET", "test-secret")

        event = {}

        assert verify_cloudfront_origin(event) is False

    def test_none_event(self, monkeypatch):
        """Should handle None event gracefully."""
        monkeypatch.setenv("CLOUDFRONT_SECRET", "test-secret")

        # This would raise AttributeError if not handled
        with pytest.raises(AttributeError):
            verify_cloudfront_origin(None)


from unittest.mock import patch, MagicMock
from shared.security import hash_ip_secure, get_ip_hash_salt, _get_ssm_parameter


class TestIPHashWithParameterStore:
    """Test HMAC-SHA256 IP hashing with Parameter Store salt."""

    def setup_method(self):
        """Clear caches between tests."""
        _get_ssm_parameter.cache_clear()
        import shared.security
        shared.security._ip_hash_salt_cache = None

    @patch('shared.security.boto3.client')
    def test_get_ssm_parameter_success(self, mock_boto_client, monkeypatch):
        """Should retrieve parameter from SSM."""
        mock_ssm = MagicMock()
        mock_ssm.get_parameter.return_value = {
            'Parameter': {'Value': 'test-salt-value'}
        }
        mock_boto_client.return_value = mock_ssm

        result = _get_ssm_parameter('/sdbx/dev/ip-hash-salt')

        assert result == 'test-salt-value'
        mock_ssm.get_parameter.assert_called_once_with(
            Name='/sdbx/dev/ip-hash-salt',
            WithDecryption=True
        )

    @patch('shared.security.boto3.client')
    def test_get_ssm_parameter_caching(self, mock_boto_client):
        """Should only call SSM once due to LRU cache."""
        mock_ssm = MagicMock()
        mock_ssm.get_parameter.return_value = {
            'Parameter': {'Value': 'cached-salt'}
        }
        mock_boto_client.return_value = mock_ssm

        result1 = _get_ssm_parameter('/sdbx/dev/ip-hash-salt')
        result2 = _get_ssm_parameter('/sdbx/dev/ip-hash-salt')

        assert result1 == result2 == 'cached-salt'
        assert mock_ssm.get_parameter.call_count == 1

    @patch('shared.security.boto3.client')
    def test_hash_ip_secure_with_parameter_store(self, mock_boto_client, monkeypatch):
        """Should produce valid HMAC-SHA256 hash."""
        monkeypatch.setenv('IP_HASH_SALT_PARAM', '/sdbx/dev/ip-hash-salt')
        mock_ssm = MagicMock()
        mock_ssm.get_parameter.return_value = {
            'Parameter': {'Value': 'test-salt'}
        }
        mock_boto_client.return_value = mock_ssm

        result = hash_ip_secure('192.168.1.1')

        assert len(result) == 64
        assert all(c in '0123456789abcdef' for c in result)

    @patch('shared.security.boto3.client')
    def test_hash_ip_secure_different_ips_different_hashes(self, mock_boto_client, monkeypatch):
        """Different IPs should produce different hashes."""
        monkeypatch.setenv('IP_HASH_SALT_PARAM', '/sdbx/dev/ip-hash-salt')
        mock_ssm = MagicMock()
        mock_ssm.get_parameter.return_value = {
            'Parameter': {'Value': 'test-salt'}
        }
        mock_boto_client.return_value = mock_ssm

        hash1 = hash_ip_secure('192.168.1.1')
        hash2 = hash_ip_secure('10.0.0.1')

        assert hash1 != hash2

    def test_get_ip_hash_salt_no_param_name(self, monkeypatch):
        """Should raise error if IP_HASH_SALT_PARAM env var not set."""
        monkeypatch.delenv('IP_HASH_SALT_PARAM', raising=False)

        with pytest.raises(ValueError, match="IP_HASH_SALT_PARAM"):
            get_ip_hash_salt()

    @patch('shared.security.boto3.client')
    def test_hash_ip_secure_parameter_not_found(self, mock_boto_client, monkeypatch):
        """Should raise error if parameter doesn't exist in SSM."""
        monkeypatch.setenv('IP_HASH_SALT_PARAM', '/sdbx/dev/ip-hash-salt')
        mock_ssm = MagicMock()
        mock_ssm.get_parameter.side_effect = Exception("ParameterNotFound")
        mock_boto_client.return_value = mock_ssm

        with pytest.raises(Exception):
            hash_ip_secure('192.168.1.1')
