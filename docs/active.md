# Active mode + audit log

The intrusive checks are opt-in twice — both flags are required:

- `--active` enables the active code paths.
- `--i-own-this-target` (or `--authorized-by <ticket-id>`) is the
  operator's attestation that they own or have **written** authorization
  to test the target.

Running with only one of the flags causes gisweep to abort with exit
code 2 and a red error message. The check catalogue lists which checks
require active mode under "Verifiable in --active".

## What the active probes do

| Check | Action | Audit action |
|---|---|---|
| ARC-002 | Atomic ``addFeatures`` + ``deleteFeatures`` (Null Island) | `feature-add`, `feature-delete` |
| ARC-004 | Vendor default-credential brute force (3 attempts max) | `default-cred-probe` |
| ARC-008 | Geometry Service ``project`` with canary URL | `geometry-ssrf-probe` |
| ARC-009 | Print Service ``Web_Map_as_JSON`` with canary URL | `print-ssrf-probe` |
| OGC-005 | ``DescribeFeatureType`` + WFS Transaction Insert/Delete | `wfs-feature-add`, `wfs-feature-delete` |

ARC-008 / ARC-009 additionally require `--ssrf-canary <url>` — a host
**you control**. gisweep does not probe internal IPs or attacker
defaults. Verification depends on observing the canary's access log;
the finding tells you to check it.

ARC-004 also requires `--auth-bruteforce` so the credential probe
cannot fire by accident.

## Audit log — `~/.gisweep/audit.jsonl`

Every active step appends one JSONL line with this stable schema:

```json
{
  "schema": "gisweep.audit.v1",
  "ts": "2026-05-03T00:00:00+00:00",
  "scan_id": "<uuid4 hex>",
  "check_id": "ARC-002",
  "action": "feature-add",
  "target_url": "...",
  "outcome": "success | failure | skipped",
  "operator": "<--i-own-this-target / --authorized-by value>",
  "details": {
      "object_id": 4242,
      "test_id": "gisweep-test-<uuid>",
      "...": "..."
  }
}
```

Sensitive details (password, token, secret, cookie) are redacted via
`gisweep.core.http.redact()` before they are written.

Override the path with the `GISWEEP_AUDIT_LOG` environment variable:

```bash
GISWEEP_AUDIT_LOG=/var/log/gisweep/audit.jsonl gisweep arcgis ... --active
```

## Cleanup

If an active write probe added a feature but the cleanup delete failed
(e.g. the network dropped between the two requests), gisweep emits a
"⚠ COULD NOT BE DELETED" finding and points you at the cleanup command:

```bash
gisweep cleanup                           # delete every orphan in the log
gisweep cleanup --scan-id <id>            # one specific scan
gisweep cleanup --dry-run                 # list orphans without deleting
gisweep cleanup --audit-log /path/to/x.jsonl
```

`gisweep cleanup` only ever issues `deleteFeatures` for entries that have
a successful `feature-add` (or `wfs-feature-add`) without a matching
successful `feature-delete` already in the audit log — so it cannot
delete features that gisweep did not create.
