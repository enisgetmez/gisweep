# gisweep

> GIS vulnerability scanner — ArcGIS REST, OGC (WMS/WFS), embedded web maps, secret
> detection, KVKK/GDPR-aware.

`gisweep` is an open-source CLI that audits GIS surfaces for the misconfigurations
nobody else looks for: ArcGIS REST services exposing anonymous write capabilities,
GeoServer/MapServer endpoints with public WFS-Transactional, admin directories
reachable from the public internet, embedded web maps leaking API keys, feature
services returning PII without authentication, and outdated server / client-side
libraries with public CVEs. Every finding is mapped to KVKK and GDPR articles so
audits are usable directly in compliance reports.

## Why

ArcGIS REST and the open-source OGC stack (GeoServer, MapServer, QGIS Server)
are everywhere — municipalities, utilities, transport, public health — and they
are *consistently* misconfigured. Existing OSS scanners (nuclei, trivy, semgrep)
do not understand ArcGIS or OGC semantics. `gisweep` fills that gap with a
protocol-aware engine plus a Playwright-driven web crawler that finds embedded
maps in the wild and follows their network traffic back to the underlying
services.

## What it covers today

| Subcommand | Targets | Checks |
|---|---|---|
| `gisweep arcgis <url>` | ArcGIS REST root | ARC-001 anonymous enumeration · ARC-002 anonymous write capability · ARC-003 admin endpoint exposed · ARC-011 Sync/Extract enabled · ARC-012 ExportTiles enabled · ARC-013 unbounded query · ARC-014 PII fields exposed · ARC-015 outdated ArcGIS Server CVE |
| `gisweep ogc <url>` | WMS / WFS via GeoServer / MapServer / QGIS Server / deegree | OGC-001 anonymous GetCapabilities · OGC-002 outdated server CVE · OGC-005 WFS-T anonymous write |
| `gisweep web <url>` | Any web page (Playwright headless Chromium) | WEB-001 embedded data-plane endpoint inventory · WEB-002 secret leakage in HTML/JS/XHR · WEB-007 outdated client-side GIS library CVE |
| `gisweep secrets <url-or-path>` | Any URL or local file/directory | SEC-001 hardcoded API keys / tokens / private keys |
| `gisweep scan <url>` | Auto-detect (probes URL, dispatches arcgis / ogc / web) | All of the above |

Cross-cutting **compliance overlay**:

- **COMP-001** KVKK Madde 12 aggregate — ≥5 PII-bearing layers exposed anonymously.
- **COMP-003** GDPR Art. 32 technical-measures gap — admin exposed AND data
  unauthenticated.

Bundled CVE database (regenerable from NIST NVD via `scripts/refresh_cve_db.py`):
ArcGIS Server, GeoServer, MapServer, plus product slots for QGIS Server,
deegree, GeoNetwork, Leaflet, OpenLayers, Mapbox GL JS, Cesium, ArcGIS API for
JavaScript.

## Output formats

- Rich console (default)
- JSON (stable schema `gisweep.report.v1`)
- SARIF 2.1.0 (consumable by GitHub Code Scanning, Azure DevOps)
- HTML (self-contained, embedded CSS, KVKK/GDPR pills)
- Markdown (GitHub-friendly, KVKK/GDPR matrix)

Every format surfaces the KVKK / GDPR / CWE / CVSS metadata of every finding.

## Install

```bash
pip install gisweep
playwright install chromium  # one-time browser download for `gisweep web`
```

Or via Docker (Playwright + Chromium pre-installed):

```bash
docker run --rm ghcr.io/enisgetmez/gisweep:latest arcgis \
    https://example.gov/arcgis/rest/services
```

## Quick start

```bash
gisweep version
gisweep checks list
gisweep checks info ARC-002

# ArcGIS REST passive scan with multi-format report
gisweep arcgis https://example.gov/arcgis/rest/services \
    -o report.json -o report.sarif -o report.html

# OGC scan against a GeoServer instance
gisweep ogc https://geo.example.org/geoserver

# Headless-Chromium audit of a city portal
gisweep web https://city-portal.example/map -o web-report.json

# Secret scan over a build directory
gisweep secrets ./build/static/js/

# Auto-detect: figure out from the URL whether to dispatch ArcGIS / OGC / web
gisweep scan https://opaque.example/something
```

## Active mode

`--active` runs intrusive checks: it actually attempts a write on a discovered
FeatureServer or WFS-T endpoint, exercises SSRF vectors via Geometry/Print
services, and probes default credentials. **It is opt-in twice** — both
`--active` and `--i-own-this-target` (or `--authorized-by <ticket>`) are
required, and every active call is appended to `~/.gisweep/audit.jsonl`.

```bash
gisweep arcgis https://my-server.example/arcgis/rest/services \
    --active --i-own-this-target \
    --ssrf-canary https://my-canary.example/abc123
```

Never run `--active` against infrastructure you do not own or have written
authorization to test. See [SECURITY.md](SECURITY.md).

## Refreshing the CVE database

```bash
uv run python -m scripts.refresh_cve_db --rate-delay 7
```

The script pulls from `services.nvd.nist.gov/rest/json/cves/2.0` for every
tracked CPE, dedupes by CVE id, and rewrites `src/gisweep/data/cve_db.json`.
Pass `--api-key <key>` for the higher NVD rate limit.

## License

[Apache-2.0](LICENSE) — © 2026 Enis Getmez and contributors.
