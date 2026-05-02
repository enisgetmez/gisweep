# Contributing to gisweep

Thanks for your interest. `gisweep` is in active development; the most useful
contributions today are new check implementations, additional secret-pattern
fingerprints, and integration test fixtures.

## Code of conduct

Be kind, be specific, attack arguments not people. Maintainers may remove
comments and ban accounts that do otherwise.

## Local setup

```bash
git clone https://github.com/enisgetmez/gisweep
cd gisweep
uv sync --all-extras
uv run pre-commit install
uv run gisweep version
```

`uv sync` provisions a virtual environment in `.venv/` and installs every
dependency including dev/docs extras.

## Running checks locally

```bash
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run mypy
```

A green `pytest --cov` (≥ 85% line, ≥ 80% branch) is required before opening a
pull request. CI runs the same on Python 3.11/3.12/3.13 across Linux, macOS,
and Windows.

## Ethical testing rules — non-negotiable

This is a security tool. Contributors agree to the following:

- **Never run `--active` against infrastructure you do not own or have written
  authorization to test.** This includes the test URLs in the design doc.
- The repository's VCR cassettes (`tests/fixtures/`) may only be **passive**
  recordings. PRs introducing recordings of state-changing requests against
  third-party hosts will be closed.
- Default-credential, SSRF, and write-test logic must keep its existing safety
  gates (double opt-in, canary-bound, redaction). PRs that loosen these are
  rejected on principle.

If your change touches `src/gisweep/checks/` you must include a test that
verifies the check's safety posture (does not POST in passive mode; respects
include/exclude filters; redacts tokens).

## Adding a check

A new check is one class plus one test. Skeleton:

```python
# src/gisweep/checks/arcgis/my_check.py
from collections.abc import AsyncIterator
from datetime import UTC, datetime

from gisweep.core import Check, Context, Finding, Severity, TargetRef, register
from gisweep.core.finding import Evidence


@register(
    id="ARC-099",
    title="Short imperative title",
    description="One paragraph explaining the issue, the impact, and how to confirm.",
    category="arcgis",
    severity=Severity.MEDIUM,
    cwe="CWE-200",
    kvkk=("m12",),
    gdpr=("art32",),
    references=("https://developers.arcgis.com/...",),
)
class MyCheck(Check):
    async def run(self, target: TargetRef, ctx: Context) -> AsyncIterator[Finding]:
        # ... do passive detection, optionally `if ctx.options.active: ...`
        if False:  # replace with real condition
            yield Finding(
                check_id=self.meta.id,
                title=self.meta.title,
                severity=self.meta.severity,
                target=target,
                description="Concrete observation including the matched value.",
                evidence=Evidence(notes=["..."]),
                remediation="Action the operator should take.",
                kvkk_articles=list(self.meta.kvkk),
                gdpr_articles=list(self.meta.gdpr),
                cwe=self.meta.cwe,
                discovered_at=datetime.now(tz=UTC),
                scan_id=ctx.scan_id,
            )
```

Then register the module in `src/gisweep/checks/__init__.py` and add a unit
test under `tests/unit/checks/arcgis/`.

## Pull request checklist

- [ ] Added or updated tests
- [ ] `uv run pytest --cov` green
- [ ] `uv run ruff check .` and `uv run ruff format --check .` clean
- [ ] `uv run mypy` clean
- [ ] Updated relevant docs (README, design spec, or check docstrings)
- [ ] Adheres to the ethical-testing rules above
