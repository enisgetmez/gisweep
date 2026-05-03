# `gisweep ogc`

```bash
gisweep ogc <url>
```

Probes WMS and WFS endpoints across the well-known path patterns
(`/geoserver/wms`, `/geoserver/wfs`, `/wms`, `/wfs`, `/cgi-bin/mapserv`,
`/mapserv`) and parses each `GetCapabilities` document via
`defusedxml`. Detects GeoServer / MapServer / QGIS Server / deegree by
fingerprinting the response.

## Active WFS-T verification

`--active --i-own-this-target` enables the OGC-005 active probe:

1. `DescribeFeatureType` on the first advertised feature type.
2. `Transaction/Insert` with a Null Island Point + unique handle.
3. `Transaction/Delete` by `ResourceId` / `FeatureId`.

Both add and delete are appended to `~/.gisweep/audit.jsonl`. If the
delete fails, the finding text directs you to `gisweep cleanup` for
manual recovery.

## Flags

Same shape as `gisweep arcgis`: `--token`, `--active`,
`--i-own-this-target`, `-o`, `--severity-threshold`, `--include`,
`--exclude`, `--proxy`, `--rate-limit`, `--timeout`, `--max-concurrency`,
`--no-verify-tls`.
