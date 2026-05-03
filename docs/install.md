# Install

## PyPI

```bash
pip install gisweep
playwright install chromium  # one-time browser download for `gisweep web`
```

The Playwright browser binaries are not bundled in the wheel — the
package depends on `playwright` so you can install them separately
when you need the `web` subcommand.

## Docker

The published image already contains Chromium and every native
dependency the headless browser needs:

```bash
docker run --rm ghcr.io/enisgetmez/gisweep:latest version
docker run --rm ghcr.io/enisgetmez/gisweep:latest \
    arcgis https://example.gov/arcgis/rest/services
```

## From source

```bash
git clone https://github.com/enisgetmez/gisweep
cd gisweep
uv sync --all-extras
uv run gisweep version
```

## Updating the bundled CVE database

The CVE database is shipped under `gisweep/data/cve_db.json`. To
refresh it from NIST NVD before a scan:

```bash
uv run python -m scripts.refresh_cve_db --rate-delay 7
```

Pass `--api-key <key>` for the higher NVD rate limit.
