"""Unit tests for the CVE database loader and version-range matcher."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest

from gisweep.cve.db import (
    CveDatabase,
    CveRecord,
    CveSeverity,
    VersionRange,
    get_cve_database,
    load_database_from_path,
)

if TYPE_CHECKING:
    from pathlib import Path


class TestVersionRange:
    @pytest.mark.parametrize(
        ("introduced", "fixed", "version", "expected"),
        [
            (None, "10.8", "10.7.1", True),
            (None, "10.8", "10.8", False),
            (None, "10.8", "10.8.1", False),
            ("10.5", "10.8", "10.6", True),
            ("10.5", "10.8", "10.4", False),
            ("10.5", None, "11.0", True),
            (None, None, "10.7", False),
            (None, "10.8", "not-a-version", False),
        ],
    )
    def test_range_matching(
        self,
        introduced: str | None,
        fixed: str | None,
        version: str,
        expected: bool,
    ) -> None:
        assert VersionRange(introduced, fixed).contains(version) is expected

    def test_exact_match(self) -> None:
        assert VersionRange(None, None, exact="10.1").contains("10.1") is True
        assert VersionRange(None, None, exact="10.1").contains("10.1.1") is False
        assert VersionRange(None, None, exact="10.1").contains("10.0") is False


class TestCveRecord:
    def _record(self, ranges: tuple[VersionRange, ...]) -> CveRecord:
        return CveRecord(
            cve_id="CVE-TEST-0001",
            summary="x",
            severity=CveSeverity.HIGH,
            cvss_score=7.5,
            cvss_vector=None,
            published=datetime(2025, 1, 1, tzinfo=UTC),
            references=(),
            ranges=ranges,
        )

    def test_affects_with_no_ranges_is_false(self) -> None:
        assert self._record(()).affects("10.0") is False

    def test_affects_when_any_range_matches(self) -> None:
        record = self._record(
            (
                VersionRange(None, "10.8"),
                VersionRange(None, None, exact="11.0"),
            )
        )
        assert record.affects("10.7") is True
        assert record.affects("11.0") is True
        assert record.affects("11.1") is False


class TestCveDatabase:
    def test_bundled_database_loads(self) -> None:
        db = get_cve_database()
        assert isinstance(db, CveDatabase)
        # bundled DB must have at least one product key, even if empty
        assert db.products

    def test_load_database_from_path(self, tmp_path: Path) -> None:
        path = tmp_path / "db.json"
        path.write_text(
            """
            {
              "schema_version": 1,
              "generated_at": "2026-05-03T00:00:00+00:00",
              "source": "test",
              "products": {
                "demo:product": [
                  {
                    "cve_id": "CVE-2020-12345",
                    "summary": "demo",
                    "severity": "high",
                    "cvss_score": 7.5,
                    "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    "published": "2020-01-01T00:00:00",
                    "references": ["https://example.com"],
                    "ranges": [{"introduced": null, "fixed": "1.2.3", "exact": null}]
                  }
                ]
              }
            }
            """,
            encoding="utf-8",
        )
        db = load_database_from_path(path)
        records = db.matching("demo:product", "1.2.0")
        assert len(records) == 1
        assert records[0].cve_id == "CVE-2020-12345"
        assert records[0].severity is CveSeverity.HIGH

    def test_empty_database_is_empty(self) -> None:
        db = CveDatabase(schema_version=1, generated_at=None, source=None, products={"x": ()})
        assert db.is_empty() is True
        assert db.matching("x", "1.0") == []
