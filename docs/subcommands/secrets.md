# `gisweep secrets`

```bash
gisweep secrets <url-or-path>
```

Two modes:

- **Local path** — walks the directory recursively, reads every file
  with a text-friendly suffix (`.js`, `.ts`, `.html`, `.json`, `.yml`,
  `.env`, …) up to 5 MiB, and runs the secret pattern catalogue across
  the contents.
- **URL** — fetches the URL with the shared HTTP client and scans the
  response body.

Each match becomes one **SEC-001** finding with the matched value
redacted (`AIza…***fghi`).

## Pattern catalogue

Vendor-anchored regexes only — no high-entropy heuristics. Patterns
covered include Google Maps / Cloud, AWS access/secret, GitHub PATs
(classic + fine-grained + app + OAuth), Stripe live secret /
restricted, Slack bot / webhook, Mapbox secret / public, ArcGIS
`?token=` URL param, JWT, generic `Authorization: Bearer …` headers,
and PEM private keys.

The catalogue ships in `src/gisweep/data/secret_patterns.yml`.

## Flags

`-o`, `--severity-threshold`, `--include`, `--exclude`, `--proxy`,
`--timeout`, `--no-verify-tls`.
