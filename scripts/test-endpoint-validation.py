from __future__ import annotations

import pytest

from scripts.lib.endpoint_validation import (
    INVALID_ENDPOINT_CASES,
    VALID_ENDPOINT_CASES,
    validate_https_endpoint,
)


def test_endpoint_validation_accepts_valid_cases() -> None:
    for value in VALID_ENDPOINT_CASES:
        validate_https_endpoint(value)


def test_endpoint_validation_rejects_invalid_cases() -> None:
    for value, message in INVALID_ENDPOINT_CASES:
        with pytest.raises(ValueError, match=message):
            validate_https_endpoint(value)
