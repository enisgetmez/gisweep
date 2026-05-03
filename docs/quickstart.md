# Quick start

Run `gisweep --help` to see every subcommand at a glance:

```text
Usage: gisweep [OPTIONS] COMMAND [ARGS]...

  GIS vulnerability scanner — ArcGIS REST, embedded maps, secret detection,
  KVKK/GDPR-aware.

Commands:
  version   Print the gisweep version.
  scan      Auto-detect the target kind and dispatch.
  arcgis    Scan an ArcGIS REST endpoint.
  ogc       Scan an OGC web service (WMS / WFS).
  web       Crawl a web page with Playwright.
  secrets   Scan a URL or local path for leaked API keys.
  checks    Inspect the built-in check catalogue.
  cleanup   Delete orphaned test features left by --active probes.
```

## A typical passive ArcGIS audit

```bash
gisweep arcgis https://example.gov/arcgis/rest/services \
    -o report.json \
    -o report.sarif \
    -o report.html \
    --severity-threshold info
```

The scanner walks every folder, service, and layer; runs the read
probe per layer; flags PII / capability / CVE issues; applies the
KVKK / GDPR compliance overlay; writes all five formats; and prints
the rich console table at the end.

## Targeted include / exclude

```bash
gisweep arcgis <url> --include ARC-001,ARC-014,ARC-018
gisweep arcgis <url> --exclude ARC-013
```

## Cross-format report

`-o` is repeatable. The format is inferred from the file extension
(`.json`, `.sarif`, `.html`, `.md`).

```bash
gisweep ogc <url> -o report.json -o report.html
```

## Auto-detect

If you don't know the target kind, let gisweep figure it out:

```bash
gisweep scan https://opaque.example.com/something
```

The `scan` subcommand probes the URL once and dispatches to `arcgis`,
`ogc`, or `web` accordingly.

## Browse the catalogue

```bash
gisweep checks list
gisweep checks list --category arcgis
gisweep checks info ARC-014
```

Every check carries severity, CWE, CVSS, KVKK articles, GDPR articles,
references, and a description string discoverable from the CLI.
