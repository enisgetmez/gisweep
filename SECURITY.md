# Security policy

## Supported versions

`gisweep` is in early development. Only the latest minor version on the `main`
branch receives security fixes. After the first stable release, this section
will pin a maintained range.

## Reporting a vulnerability

Email **enis@enisgetmez.com** with the subject line `gisweep security`. Do not
open a public GitHub issue for vulnerabilities. Expect an acknowledgment within
3 working days and a remediation plan within 14 days. Coordinated disclosure
is preferred; we will credit reporters in the changelog unless they prefer to
remain anonymous.

## Ethical use

`gisweep` is a defensive and authorized-pentest tool. The maintainers do not
support and will not assist with use against systems for which the operator
lacks written authorization.

The scanner enforces the following safeguards:

- **Passive by default.** No POST, no state-changing request, ever, without
  the explicit `--active` flag.
- **Active mode requires double opt-in.** Both `--active` and
  `--i-own-this-target` (or `--authorized-by <ticket-id>`) must be passed. The
  ticket id is recorded in the audit log.
- **SSRF testing is canary-bound.** Geometry-service and print-service SSRF
  checks only run when the operator supplies their own callback host via
  `--ssrf-canary`. The scanner never probes internal IP ranges, localhost, or
  cloud metadata endpoints.
- **Default-credential brute force is opt-in and rate-limited.** The wordlist
  contains only vendor defaults (esri/esri, admin/admin, siteadmin/siteadmin)
  and stops after three attempts per host to avoid lockout.
- **Active write tests are atomic.** ARC-002 inserts a single test feature at
  Null Island, immediately deletes it by `OBJECTID`, and retries deletion on
  exception. If cleanup fails, the operator is alerted with a `gisweep cleanup`
  command and a kept scan id.
- **Tokens are redacted.** Authorization headers, cookies, and `?token=` URL
  parameters are reduced to a fingerprint (`***x4y2`) before being written to
  any output, log, or audit entry.
- **Audit log.** Every `--active` invocation appends to
  `~/.gisweep/audit.jsonl` with timestamp, target, action, outcome, and any
  authorization ticket id supplied.

If you find a way to subvert these safeguards, treat it as a security
vulnerability and report it via the channel above.

## Responsible testing — guidance for operators

When auditing third parties, always:

1. Obtain written authorization that names the target hosts, the time window,
   and the techniques permitted.
2. Run with `--passive` until the scope is confirmed; only then move to
   `--active`.
3. Provide your own SSRF canary host; never use a host you do not control.
4. Coordinate with the operations team if `--auth-bruteforce` may trigger
   their lockout policy.
