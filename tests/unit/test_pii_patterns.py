"""Unit tests for the PII matcher."""

from __future__ import annotations

import pytest

from gisweep.patterns.pii import PiiMatcher, get_pii_matcher


@pytest.fixture
def matcher() -> PiiMatcher:
    return get_pii_matcher()


@pytest.mark.parametrize(
    ("name", "expected_label"),
    [
        ("TCKN", "Turkish national identity number"),
        ("tc_kimlik_no", "Turkish national identity number"),
        ("email", "Email address"),
        ("eposta", "Email address"),
        ("telefon", "Phone number"),
        ("gsm", "Phone number"),
        ("adres", "Street address"),
        ("dogum_tarihi", "Date of birth"),
        ("iban", "IBAN / bank account"),
        ("vergi_no", "Tax / VAT number"),
        ("din", "Religion / belief"),
        ("etnik", "Ethnicity / race"),
    ],
)
def test_match_field_known_patterns(matcher: PiiMatcher, name: str, expected_label: str) -> None:
    matches = matcher.match_field(name=name)
    labels = [m.pattern.label for m in matches]
    assert expected_label in labels


def test_match_field_unrelated_name_returns_empty(matcher: PiiMatcher) -> None:
    assert matcher.match_field(name="parcel_geometry") == []


def test_match_field_via_alias(matcher: PiiMatcher) -> None:
    matches = matcher.match_field(name="X1", alias="E-Posta")
    assert any(m.pattern.id == "email" for m in matches)


def test_value_match_iban(matcher: PiiMatcher) -> None:
    matches = matcher.match_value("TR330006100519786457841326")
    assert any(m.pattern.id == "iban" for m in matches)


def test_sensitive_flag_for_health_field(matcher: PiiMatcher) -> None:
    matches = matcher.match_field(name="kan_grubu")
    assert any(m.pattern.sensitive for m in matches)
