# `gisweep scan`

```bash
gisweep scan <url>
```

Auto-detects the target kind by:

1. Inspecting the URL pattern (`/arcgis/rest/services` →
   `arcgis`; `/geoserver/wms` etc. → `ogc`).
2. Fetching the URL once and looking at `Content-Type` plus a body
   excerpt (JSON with `currentVersion` → `arcgis`; XML with
   `WMS_Capabilities` → `ogc`; HTML → `web`).

Whatever it picks, it forwards the request to the matching subcommand
runtime (`arcgis`, `ogc`, or `web`). Use this when you don't know the
shape of the target.

## Flags

A small surface — every detail-level flag should be passed through to
the dedicated subcommand instead.

| Flag | Effect |
|---|---|
| `-o / --output <file>` | Forwarded to the dispatched runtime. |
| `--timeout <s>` | HTTP timeout (used by both detection and downstream). |
| `--no-verify-tls` | Disable TLS verification. |
