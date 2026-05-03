# Output formats

The `-o`/`--output` flag is repeatable. Each value is either a file
path (extension implies the format) or a `format:path` tuple.

```bash
gisweep arcgis <url> \
    -o report.json \
    -o report.sarif \
    -o report.html \
    -o report.md
```

## Console

The default. A rich-formatted table with severity colour bands, a
duration / count summary, and a "Compliance" column listing KVKK / GDPR
articles per row.

## JSON — `gisweep.report.v1`

Stable schema, two top-level keys:

```jsonc
{
  "schema": "gisweep.report.v1",
  "meta": {
    "scan_id": "...",
    "started_at": "...",
    "finished_at": "...",
    "duration_seconds": 1.23,
    "targets": ["..."],
    "gisweep_version": "0.1.0",
    "exit_code": 1,
    "counts_by_severity": { "info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0 }
  },
  "findings": [ /* Finding objects */ ]
}
```

Use this for CI / automation. The Finding shape is documented in
`src/gisweep/core/finding.py::Finding`.

## SARIF 2.1.0

Consumable by GitHub Code Scanning, Azure DevOps, GitLab Advanced
Security, and any other SARIF-aware tool. Each `result` is enriched
with `properties.compliance.kvkk` and `properties.compliance.gdpr`
arrays so consumers can filter by compliance dimension. The
`runs[0].taxonomies` array carries KVKK and GDPR taxonomy entries.

## HTML

Single self-contained file: inline CSS, no JavaScript, severity
"donuts" rendered with pure CSS. Each finding card includes KVKK
and GDPR pills, and the report opens with a Compliance × check
matrix so reviewers can see the article coverage at a glance.

## Markdown

GitHub-friendly. Renders the severity summary table, KVKK/GDPR
matrix, and one section per finding. Designed to paste cleanly into
issue trackers or compliance reports.
