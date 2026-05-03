# `gisweep web`

```bash
gisweep web <url>
```

Loads a single page in headless Chromium (Playwright), captures the
network request log, sniffs `script` / `document` / `xhr` response
bodies, and reads the canonical version global of every well-known
GIS library (Leaflet, OpenLayers, Mapbox GL, Cesium, ArcGIS API for
JavaScript).

The captured `WebDiscoveryResult` powers seven WEB-* checks:

- **WEB-001** Embedded map data-plane endpoint inventory
- **WEB-002** Secret leak in browser-loaded source
- **WEB-003** Permissive CORS on a discovered data-plane endpoint
- **WEB-004** Mixed content (HTTPS page → HTTP resource)
- **WEB-005** Third-party script loaded without Subresource Integrity
- **WEB-006** Iframe without `sandbox`
- **WEB-007** Outdated client-side GIS library with known CVE

## Flags

| Flag | Effect |
|---|---|
| `--headed` | Show a visible Chromium window (default headless). |
| `--user-agent <UA>` | Override the default browser User-Agent. |
| `-o`, `--severity-threshold`, `--include`, `--exclude`, `--proxy`, `--timeout`, `--no-verify-tls` | Same as the other subcommands. |

## First-run note

`gisweep web` requires the Playwright Chromium binary. Install it once:

```bash
playwright install chromium
```

The Docker image already includes it.
