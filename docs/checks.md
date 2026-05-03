# Check catalogue

The runtime catalogue is always discoverable from the CLI:

```bash
gisweep checks list
gisweep checks list --category arcgis
gisweep checks info ARC-002
```

This page summarises the v1 catalogue (24 checks across four categories
plus four compliance overlay rules and SEC-001 from the secrets
matcher).

## ArcGIS (14)

| ID | Severity | Description |
|---|---|---|
| ARC-001 | info | Anonymous service enumeration |
| ARC-002 | critical | Anonymous write capability (passive + active verified) |
| ARC-003 | critical | Admin endpoint reachable |
| ARC-004 | critical | Default credentials accepted (active + gated) |
| ARC-008 | high | Geometry Service SSRF (active + canary) |
| ARC-009 | high | Print Service SSRF (active + canary) |
| ARC-011 | medium | Sync / Extract enabled |
| ARC-012 | low | ExportTiles enabled |
| ARC-013 | high / medium | Layer query unbounded |
| ARC-014 | critical / high / medium | PII fields exposed |
| ARC-015 | varies | Outdated ArcGIS Server CVE |
| ARC-016 | high / critical | Public Portal item carries PII metadata |
| ARC-017 | info | Layer anonymously readable (confirmed) |
| ARC-018 | info | REST inventory rollup |

## OGC (3)

| ID | Severity | Description |
|---|---|---|
| OGC-001 | info | Anonymous WMS/WFS GetCapabilities |
| OGC-002 | varies | Outdated GeoServer / MapServer / QGIS Server CVE |
| OGC-005 | critical | WFS-T anonymous write (passive + active verified) |

## Web (7)

| ID | Severity | Description |
|---|---|---|
| WEB-001 | info | Embedded data-plane endpoint inventory |
| WEB-002 | high | Secret leak in browser-loaded source |
| WEB-003 | high | Permissive CORS (reflected origin / `*` + credentials) |
| WEB-004 | medium | Mixed content (HTTPS → HTTP) |
| WEB-005 | low | Missing SRI on third-party script |
| WEB-006 | low | Iframe without sandbox |
| WEB-007 | varies | Outdated client-side GIS library CVE |

## Secrets (1)

| ID | Severity | Description |
|---|---|---|
| SEC-001 | varies | Hardcoded API key / token / private key in source |

Secret patterns are vendor-anchored: Google Maps, AWS access/secret,
GitHub PATs (classic + fine-grained + app + OAuth), Stripe live secret/
restricted, Slack bot/webhook, Mapbox secret/public, ArcGIS `?token=`
URL param, JWT, generic Bearer header, PEM private keys.

## Compliance overlay (4)

| ID | Severity | Trigger |
|---|---|---|
| COMP-001 | critical | ≥5 ARC-014 PII findings |
| COMP-002 | medium | Host outside KVKK / GDPR safe-transfer list |
| COMP-003 | critical | ARC-003 admin AND any data-plane finding |
| COMP-004 | high | ARC-014 PII finding on a point-geometry layer |
