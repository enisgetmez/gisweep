# `gisweep cleanup`

```bash
gisweep cleanup [--scan-id ID] [--audit-log PATH] [--dry-run]
```

Walks `~/.gisweep/audit.jsonl`, finds entries where a
`feature-add` (or `wfs-feature-add`) succeeded but no matching
`feature-delete` (or `wfs-feature-delete`) success was ever recorded,
and tries to delete each orphan via `deleteFeatures` /
`Transaction/Delete`.

The command is non-destructive in the strict sense — it only ever
deletes features whose `layer_url` + `object_id` + `test_id` triple
came from a prior gisweep `--active` run. Manually-created features
are not at risk.

## Flags

| Flag | Effect |
|---|---|
| `--scan-id <id>` | Restrict cleanup to a single scan. |
| `--audit-log <path>` | Override the audit log path (default `~/.gisweep/audit.jsonl`, `GISWEEP_AUDIT_LOG` env var). |
| `--dry-run` | List orphans without deleting. |
| `--timeout <s>` | HTTP timeout. |
| `--no-verify-tls` | Disable TLS verification. |

Each cleanup attempt — pass or fail — is itself appended to the audit
log as `feature-cleanup`, so the trail stays complete.
