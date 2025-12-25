"""Shared pytest fixtures and configuration."""

import os
import sys
import pytest

# Add parent directory to path so we can import shared modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


@pytest.fixture(autouse=True)
def clean_environment(monkeypatch):
    """Clean environment variables before each test."""
    # Clear any existing AWS/CloudFront secrets
    monkeypatch.delenv("CLOUDFRONT_SECRET", raising=False)
    monkeypatch.delenv("RECAPTCHA_SECRET_KEY", raising=False)
    monkeypatch.delenv("RECAPTCHA_MIN_SCORE", raising=False)


# Mark all tests in tests/ as unit tests by default
def pytest_collection_modifyitems(items):
    """Automatically mark tests based on location."""
    for item in items:
        # Add 'unit' marker to all tests by default
        if "integration" not in item.keywords and "slow" not in item.keywords:
            item.add_marker(pytest.mark.unit)
