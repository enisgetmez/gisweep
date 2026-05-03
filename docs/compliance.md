# Compliance overlay

Every Finding already carries KVKK and GDPR article references via the
check's `@register` metadata. The compliance overlay sits on top of
that and emits **aggregate** findings — situations where a single
issue alone would not constitute a violation but a combination does.

## COMP-001 — KVKK Madde 12 aggregate

Fires when **five or more ARC-014 PII findings** appear in the same
scan. Severity CRITICAL, KVKK m12 / GDPR Art 32.

> Five layers exposing personal data without authentication is the
> signal that the deployment as a whole has failed KVKK Madde 12's
> obligation to take "all necessary technical and organisational
> measures". One layer might be a misconfig; five is a pattern.

## COMP-002 — Cross-border transfer

Fires when one or more PII / data-bearing findings live on a host that
resolves (via `ipapi.co`) to a country **outside** the bundled KVKK or
GDPR safe-transfer destinations. Severity MEDIUM, KVKK m9 / GDPR Ch V.

The bundled list is stored in
`gisweep/data/country_codes.yml` and contains:

- **KVKK safe**: TR + EU/EEA member states.
- **GDPR safe**: EU/EEA + the European Commission's adequacy decisions
  (UK, CH, AD, AR, CA, FO, GG, IL, IM, JP, JE, NZ, KR, UY).

Lookups are cached per scan. If `ipapi.co` is unreachable, the rule
stays silent — false negatives are preferred over false positives that
would force you to ignore the check.

## COMP-003 — GDPR Art 32 technical-measures gap

Fires when **ARC-003 (admin endpoint exposed) AND any of {ARC-001,
ARC-002, ARC-014, OGC-005}** co-occur in the same scan. Severity
CRITICAL.

> An exposed admin directory plus anonymously-readable data services is
> exactly the pattern Article 32 is meant to prevent.

## COMP-004 — Re-identification risk

Fires when an **ARC-014 PII finding** is on a layer whose evidence
flags a high-precision geometry (point — sub-metre coordinates).
Severity HIGH, GDPR Art 4(1) + 32.

> Coordinate precision under a few metres is enough to single out a
> household. Combined with PII fields like TCKN or e-mail, the dataset
> can re-identify individuals even when names are absent.

## Output

Every report writer surfaces COMP-* findings alongside the per-check
findings. The HTML, Markdown, and SARIF outputs include a "Compliance
impact" matrix at the top so a reviewer can see at a glance which KVKK
articles and GDPR articles were engaged across the scan.
