"""Unit tests for the HTTP client helpers (redaction, header allowlist).

Network calls themselves are exercised in Phase 2 with respx-mocked fixtures.
"""

from __future__ import annotations

import httpx
import pytest

from gisweep.core.http import (
    HttpClient,
    redact,
    redact_request_headers,
    safe_response_headers,
)
from gisweep.core.options import ScanOptions


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("", ""),
        ("abc", "***"),
        ("Bearer ABCDEFGH1234", "***1234"),
        ("bearer ABCDEFGH1234", "***1234"),
        ("ABCDEF", "***"),
        ("ABCDEFGH", "***EFGH"),
    ],
)
def test_redact_fingerprints_safely(value: str, expected: str) -> None:
    assert redact(value) == expected


def test_redact_request_headers_targets_only_secret_headers() -> None:
    headers = {
        "Authorization": "Bearer ABCDEFGH1234",
        "Cookie": "session=ABCDEFGH",
        "User-Agent": "gisweep/0.1.0",
        "Accept": "application/json",
    }
    redacted = redact_request_headers(headers)
    assert redacted["Authorization"] == "***1234"
    assert redacted["Cookie"] == "***EFGH"
    assert redacted["User-Agent"] == "gisweep/0.1.0"
    assert redacted["Accept"] == "application/json"


def test_safe_response_headers_drops_unlisted() -> None:
    raw = httpx.Headers(
        {
            "Content-Type": "application/json",
            "Server": "Apache",
            "Set-Cookie": "session=secret",
            "X-Internal-ID": "should-be-stripped",
        }
    )
    safe = safe_response_headers(raw)
    assert "content-type" in safe
    assert "server" in safe
    assert "set-cookie" not in safe
    assert "x-internal-id" not in safe


@pytest.mark.asyncio
async def test_http_client_aclose_is_idempotent_via_context_manager() -> None:
    async with HttpClient(ScanOptions()) as client:
        assert client._semaphore._value > 0
