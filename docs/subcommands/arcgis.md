# `gisweep arcgis`

```bash
gisweep arcgis <url>
```

Walks the ArcGIS REST root, enumerates every folder / service /
layer, and runs the 14 ArcGIS-aware checks against each appropriate
target. The walker auto-corrects `…/arcgis/rest` to `…/arcgis/rest/services`
when needed and prints a discovery summary line before checks run.

## Auth

| Flag | Effect |
|---|---|
| `--token <T>` | Pass an existing ArcGIS token; appended both as `?token=` URL param and `X-Esri-Authorization: Bearer` header. |
| `--username U --password P` | Exchange credentials for a token via `<portal>/sharing/rest/generateToken`. |
| `--portal-url <URL>` | Override the portal root used for `generateToken`. Defaults to the host portion of the target URL. |
| `--referer <URL>` | Bind the issued token to a Referer (some Enterprise deployments require this). |

## Active mode

| Flag | Effect |
|---|---|
| `--active` | Enables the active probes: ARC-002 atomic add+delete, ARC-004 default-cred brute force (with `--auth-bruteforce`), ARC-008 / ARC-009 SSRF (with `--ssrf-canary`). |
| `--i-own-this-target` | Required with `--active`; affirms ownership / written authorization. |
| `--auth-bruteforce` | Required for ARC-004; vendor wordlist only, 3 attempts max. |
| `--ssrf-canary <url>` | Required for ARC-008 / ARC-009; the operator-supplied callback host. |

See [Active mode + audit log](../active.md) for the full safety
contract.

## Output / filtering

| Flag | Effect |
|---|---|
| `-o / --output <file>` | Repeatable. Format inferred from extension (`.json`, `.sarif`, `.html`, `.md`) or use `format:path`. |
| `--severity-threshold {info,low,medium,high,critical}` | Drop findings below this severity. |
| `--include ID,ID,…` | Run only these check ids. |
| `--exclude ID,ID,…` | Skip these check ids. |
| `--proxy <url>` | HTTP/SOCKS proxy. |
| `--rate-limit <rps>` | Per-host requests-per-second cap. |
| `--timeout <s>` | HTTP timeout. |
| `--max-concurrency <n>` | Concurrent in-flight requests. |
| `--max-depth <n>` | Folder recursion depth (default 5). |
| `--no-verify-tls` | Disable TLS verification (use sparingly). |
