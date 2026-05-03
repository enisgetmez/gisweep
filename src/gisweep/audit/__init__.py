"""Audit log for ``--active`` operations.

Every check that exercises a state-changing or credential-touching code path
appends a JSONL record to ``~/.gisweep/audit.jsonl`` so the operator (and any
later forensic review) has an authoritative trail of what gisweep actually
did against the target.
"""

from gisweep.audit.log import (
    AuditEntry,
    AuditOutcome,
    audit_log_path,
    write_audit_entry,
)

__all__ = [
    "AuditEntry",
    "AuditOutcome",
    "audit_log_path",
    "write_audit_entry",
]
