"""Unit tests for the secret matcher and redaction helper."""

from __future__ import annotations

import pytest

from gisweep.patterns.secrets import SecretMatcher, get_secret_matcher, redact_secret


@pytest.fixture
def matcher() -> SecretMatcher:
    return get_secret_matcher()


@pytest.mark.parametrize(
    ("text", "expected_id"),
    [
        ("apiKey: AIzaSyA1234567890ABCDEFGHIJKLMNOPQRSTUVWX", "google-maps-api-key"),
        ("AKIAIOSFODNN7EXAMPLE used as access key", "aws-access-key-id"),
        ("token=ghp_abcdefghijklmnopqrstuvwxyz1234567890", "github-pat-classic"),
        ("Stripe live key " "sk_" "live_" "FAKEPLACEHOLDER0000FAKEPLACE", "stripe-secret-live"),
        (
            "https://" "hooks.slack.com/services/"
            "T00FAKEFAKE0" "/B00FAKEFAKE0" "/FAKEPLACEHOLDERtokenFAKE",
            "slack-webhook",
        ),
        (
            "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
            "jwt",
        ),
        ("?token=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "arcgis-token-url-param"),
        (
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEogIBAAKCAQEA",
            "private-key-pem",
        ),
    ],
)
def test_matcher_finds_known_secret(matcher: SecretMatcher, text: str, expected_id: str) -> None:
    matches = matcher.scan(text)
    ids = {m.pattern.id for m in matches}
    assert expected_id in ids, f"expected {expected_id} in {ids}"


def test_matcher_ignores_random_text(matcher: SecretMatcher) -> None:
    text = "the quick brown fox 12345 jumps over the lazy dog"
    assert matcher.scan(text) == []


def test_matcher_skips_too_short_token(matcher: SecretMatcher) -> None:
    assert matcher.scan("?token=short") == []


def test_redact_secret_handles_short_input() -> None:
    assert redact_secret("abc") == "***"


def test_redact_secret_keeps_prefix_and_suffix_only() -> None:
    redacted = redact_secret("AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi")
    assert redacted.startswith("AIza")
    assert redacted.endswith("fghi")
    assert "***" in redacted
