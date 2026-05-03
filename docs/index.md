# gisweep

> GIS vulnerability scanner — ArcGIS REST, OGC (WMS/WFS), embedded web maps,
> secret detection, KVKK/GDPR-aware.

`gisweep` is an open-source CLI that audits GIS surfaces for the
misconfigurations nobody else looks for: ArcGIS REST services exposing
anonymous write capabilities, GeoServer/MapServer endpoints with public
WFS-Transactional, admin directories reachable from the public internet,
embedded web maps leaking API keys, feature services returning PII without
authentication, and outdated server / client-side libraries with public
CVEs. **Every finding is mapped to KVKK and GDPR articles**, so audits are
usable directly in compliance reports.

## What it covers today

| Subcommand | Targets | Checks |
|---|---|---|
| `gisweep arcgis <url>` | ArcGIS REST root | ARC-001…ARC-018 (14 checks) |
| `gisweep ogc <url>` | WMS / WFS via GeoServer / MapServer / QGIS Server | OGC-001 / OGC-002 / OGC-005 |
| `gisweep web <url>` | Any web page (Playwright headless Chromium) | WEB-001…WEB-007 |
| `gisweep secrets <url-or-path>` | Any URL or local file/directory | SEC-001 hardcoded secrets |
| `gisweep scan <url>` | Auto-detect → arcgis / ogc / web | All of the above |
| `gisweep cleanup` | Audit log | Delete orphaned `--active` test features |

Cross-cutting **compliance overlay** automatically applies when any
finding fires:

- **COMP-001** KVKK Madde 12 aggregate (≥5 PII layers exposed anonymously)
- **COMP-002** Cross-border transfer (KVKK m9 / GDPR Chapter V)
- **COMP-003** GDPR Art. 32 technical-measures gap
- **COMP-004** Re-identification risk (PII + high-precision geometry)

## Five output formats — every one carries the KVKK / GDPR metadata

- Rich console (default)
- JSON (stable schema `gisweep.report.v1`)
- SARIF 2.1.0 (consumable by GitHub Code Scanning, Azure DevOps)
- HTML (self-contained, embedded CSS, KVKK/GDPR pills)
- Markdown (GitHub-friendly, KVKK/GDPR matrix)

## Safe by default

`gisweep` is passive by default. The intrusive checks (write probes,
default-credential brute-force, SSRF probes) require **double opt-in**:
both `--active` and `--i-own-this-target` (or `--authorized-by <ticket>`)
must be passed, and every active call is appended to
`~/.gisweep/audit.jsonl` for forensic review. SSRF probes additionally
require an operator-supplied `--ssrf-canary` host.

Read [Security](security.md) before running `--active` against anything.

## Next steps

- [Install gisweep](install.md)
- [Quick start with the CLI](quickstart.md)
- [Browse the check catalogue](checks.md)
