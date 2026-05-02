# gisweep

> GIS vulnerability scanner — ArcGIS REST, embedded maps, secret detection, KVKK/GDPR-aware.

`gisweep` is an open-source CLI that audits GIS surfaces for the misconfigurations
nobody else looks for: ArcGIS REST services exposing anonymous write capabilities,
admin endpoints reachable from the public internet, embedded web maps leaking API
keys, feature services returning PII without authentication. Every finding is
mapped to KVKK and GDPR articles so audits are usable directly in compliance
reports.

> **Status:** early development. The check catalogue lands in Phase 2.

## Why

ArcGIS REST is everywhere — municipalities, utilities, transport, public health —
and it is *consistently* misconfigured. Existing OSS scanners (nuclei, trivy,
semgrep) do not understand ArcGIS semantics, and Esri's own tooling is closed
and operator-side. `gisweep` fills that gap with an ArcGIS-aware engine plus a
Playwright-driven crawler that finds embedded maps in the wild and follows
their network traffic back to the underlying services.

## Features (target)

- **ArcGIS REST scanner** — auth & permissions, service-level abuse, info
  disclosure, outdated server CVEs
- **Web crawler with Playwright** — discovers ArcGIS / Mapbox / Leaflet endpoints
  embedded in any page; sniffs network for hidden services
- **Secret detection** — Google Maps, ArcGIS, Mapbox, AWS, GitHub PAT, JWT,
  Slack, Stripe; entropy + regex + verification
- **KVKK / GDPR overlay** — every finding tagged with the violated articles,
  surfaced in every output format
- **5 output formats** — rich console, JSON, SARIF 2.1.0, single-file HTML,
  Markdown
- **Plugin-based registry** — adding a check is ~50 lines; entry-points let
  third parties ship their own check packs on PyPI
- **Safe by default** — passive fingerprinting only; `--active` requires
  explicit ownership / authorization flags and writes to an audit log

## Install

```bash
pip install gisweep
gisweep install-browsers   # one-time Playwright chromium download
```

Or via Docker:

```bash
docker run --rm ghcr.io/enisgetmez/gisweep arcgis https://example.gov/arcgis/rest/services
```

## Quick start

```bash
gisweep version
gisweep checks list
gisweep checks info ARC-002

gisweep arcgis https://example.gov/arcgis/rest/services \
    -o report.json -o report.sarif -o report.html

gisweep web https://city-portal.example/map \
    --depth 2

gisweep secrets ./build/static/js/
```

## Active mode

`--active` runs intrusive checks: it actually attempts a write on a discovered
FeatureServer, exercises SSRF vectors via Geometry/Print services, and probes
default credentials. **It is opt-in twice** — both `--active` and
`--i-own-this-target` (or `--authorized-by <ticket>`) are required, and every
active call is appended to `~/.gisweep/audit.jsonl`.

```bash
gisweep arcgis https://my-server.example/arcgis/rest/services \
    --active --i-own-this-target \
    --ssrf-canary https://my-canary.example/abc123
```

Never run `--active` against infrastructure you do not own or have written
authorization to test. See [SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE) — © 2026 Enis Getmez and contributors.
