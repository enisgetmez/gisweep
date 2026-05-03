"""OGC-005 — WFS Transactional operations exposed without authentication.

Passive: when the WFS GetCapabilities document advertises the ``Transaction``
or ``LockFeature`` operation and the endpoint was reached without
authentication, emit a critical finding.

Active (``--active --i-own-this-target``): runs ``DescribeFeatureType`` on
the first feature type, constructs a minimal ``Transaction/Insert`` payload
with just a Point geometry, captures the ``insertResults`` handle, then
``Transaction/Delete`` by ``ResourceId``. Every step is appended to the
shared audit log under actions ``wfs-feature-add`` / ``wfs-feature-delete``
and the resulting Finding describes whether the cleanup completed.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import httpx
from defusedxml import ElementTree as Det

from gisweep.audit import AuditEntry, AuditOutcome, write_audit_entry
from gisweep.checks.arcgis._helpers import has_anonymous_token
from gisweep.checks.ogc._helpers import cached_capabilities
from gisweep.core import Severity
from gisweep.core.check import Check
from gisweep.core.finding import Evidence, Finding, TargetKind, TargetRef
from gisweep.core.registry import register

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from gisweep.core.context import Context
    from gisweep.discovery.ogc_enum import OgcCapabilities

_TRANSACTION_OPERATIONS: frozenset[str] = frozenset({"Transaction", "LockFeature"})
_HTTP_OK = 200


@dataclass(frozen=True, slots=True)
class WfsTransactionVerification:
    added: bool
    deleted: bool
    feature_id: str | None
    type_name: str | None
    error: str | None = None


@register(
    id="OGC-005",
    title="WFS Transactional operations exposed without authentication",
    description=(
        "The WFS endpoint advertises ``Transaction`` (and possibly "
        "``LockFeature``) in its OperationsMetadata, meaning anonymous "
        "callers may be able to insert, update, or delete features. The "
        "passive detection inspects only the capabilities document; "
        "running with ``--active --i-own-this-target`` performs an atomic "
        "Insert + Delete probe against the first feature type to confirm."
    ),
    category="ogc",
    severity=Severity.CRITICAL,
    cwe="CWE-862",
    cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    kvkk=("m12",),
    gdpr=("art32", "art5-1-f"),
    references=("https://www.ogc.org/standards/wfs",),
    target_kinds=("ogc_service",),
    needs_active=False,
    can_verify_active=True,
    tags=("anonymous", "write", "ogc", "wfs-t"),
)
class WfsTransactionalCheck(Check):
    async def run(
        self,
        target: TargetRef,
        ctx: Context,
    ) -> AsyncIterator[Finding]:
        if target.kind != TargetKind.OGC_SERVICE:
            return
        if not has_anonymous_token(ctx):
            return
        for cap in cached_capabilities(ctx):
            if cap.endpoint_url != target.url or cap.service != "WFS":
                continue
            transactional_ops = cap.operations & _TRANSACTION_OPERATIONS
            if not transactional_ops:
                continue

            verification: WfsTransactionVerification | None = None
            if ctx.options.active and ctx.options.i_own_this_target:
                verification = await _verify_wfs_transaction(ctx, cap, self.meta.id)

            notes = [
                f"wfs_version={cap.version}",
                f"feature_types={len(cap.layers)}",
                f"operations={','.join(sorted(cap.operations))}",
            ]
            if verification is not None:
                notes.extend(
                    [
                        f"active_added={verification.added}",
                        f"active_deleted={verification.deleted}",
                        f"active_feature_id={verification.feature_id!r}",
                        f"active_type_name={verification.type_name!r}",
                    ]
                )
                if verification.error:
                    notes.append(f"active_error={verification.error}")

            if verification is not None and verification.added:
                delete_state = (
                    "was successfully deleted"
                    if verification.deleted
                    else "⚠ COULD NOT BE DELETED — see audit log and run "
                    "`gisweep cleanup` manually for this WFS-T"
                )
                description = (
                    f"`{cap.endpoint_url}` accepted an anonymous WFS-T Insert on "
                    f"`{verification.type_name}` (resourceId={verification.feature_id}); "
                    f"the feature {delete_state}. WFS Transactional write capability "
                    "is **verified**."
                )
            elif verification is not None:
                description = (
                    f"`{cap.endpoint_url}` advertises {', '.join(sorted(transactional_ops))} "
                    f"in its WFS {cap.version} OperationsMetadata, but the active probe "
                    f"failed: {verification.error or 'rejected'}. Capability is set; "
                    "the data plane may still require auth."
                )
            else:
                description = (
                    f"`{cap.endpoint_url}` advertises {', '.join(sorted(transactional_ops))} "
                    f"in its WFS {cap.version} OperationsMetadata. The endpoint was "
                    "reached without authentication, so anonymous callers may be able to "
                    "insert, modify, or delete features. Re-run with ``--active "
                    "--i-own-this-target`` to confirm."
                )

            yield Finding(
                check_id=self.meta.id,
                title=self.meta.title,
                severity=self.meta.severity,
                target=target,
                description=description,
                evidence=Evidence(
                    matched=",".join(sorted(transactional_ops)),
                    notes=notes,
                ),
                remediation=(
                    "Restrict WFS-T to authenticated, role-scoped users. In "
                    "GeoServer this is configured via Security → Data → Service "
                    "Access Rules; in MapServer/QGIS Server, gate the endpoint "
                    "with a token-aware reverse proxy."
                ),
                references=list(self.meta.references),
                cwe=self.meta.cwe,
                cvss_vector=self.meta.cvss_vector,
                kvkk_articles=list(self.meta.kvkk),
                gdpr_articles=list(self.meta.gdpr),
                tags=list(self.meta.tags),
                discovered_at=datetime.now(tz=UTC),
                scan_id=ctx.scan_id,
            )


async def _verify_wfs_transaction(
    ctx: Context,
    cap: OgcCapabilities,
    check_id: str,
) -> WfsTransactionVerification:
    if not cap.layers:
        return WfsTransactionVerification(
            added=False,
            deleted=False,
            feature_id=None,
            type_name=None,
            error="no feature types advertised",
        )
    type_name = cap.layers[0].name
    operator = (
        ctx.options.auth.referer
        if ctx.options.auth and ctx.options.auth.referer
        else "owner-attestation"
    )

    schema = await _describe_feature_type(ctx, cap.endpoint_url, type_name)
    if schema is None:
        return WfsTransactionVerification(
            added=False,
            deleted=False,
            feature_id=None,
            type_name=type_name,
            error="DescribeFeatureType failed",
        )

    handle = f"gisweep-{uuid.uuid4().hex}"
    insert_xml = _build_insert_xml(cap.version, type_name, schema, handle)

    add_outcome = AuditOutcome.FAILURE
    feature_id: str | None = None
    add_error: str | None = None
    try:
        response = await ctx.http.post(
            cap.endpoint_url,
            content=insert_xml.encode("utf-8"),
            headers={"Content-Type": "application/xml"},
        )
        if response.status_code == _HTTP_OK:
            feature_id = _parse_insert_response(response.text)
            if feature_id:
                add_outcome = AuditOutcome.SUCCESS
            else:
                add_error = _extract_xml_error(response.text) or "no resourceId returned"
        else:
            add_error = f"http_{response.status_code}"
    except (httpx.HTTPError, OSError, ValueError) as exc:
        add_error = str(exc)

    write_audit_entry(
        AuditEntry(
            scan_id=ctx.scan_id,
            check_id=check_id,
            action="wfs-feature-add",
            target_url=cap.endpoint_url,
            outcome=add_outcome,
            operator=operator,
            details={
                "type_name": type_name,
                "feature_id": feature_id,
                "handle": handle,
                "error": add_error,
            },
        )
    )

    if feature_id is None:
        return WfsTransactionVerification(
            added=False,
            deleted=False,
            feature_id=None,
            type_name=type_name,
            error=add_error,
        )

    delete_xml = _build_delete_xml(cap.version, type_name, feature_id)
    delete_outcome = AuditOutcome.FAILURE
    delete_error: str | None = None
    try:
        del_response = await ctx.http.post(
            cap.endpoint_url,
            content=delete_xml.encode("utf-8"),
            headers={"Content-Type": "application/xml"},
        )
        if del_response.status_code == _HTTP_OK and "totalDeleted" in del_response.text:
            delete_outcome = AuditOutcome.SUCCESS
        elif del_response.status_code == _HTTP_OK:
            delete_error = _extract_xml_error(del_response.text) or "delete unconfirmed"
        else:
            delete_error = f"http_{del_response.status_code}"
    except (httpx.HTTPError, OSError, ValueError) as exc:
        delete_error = str(exc)

    write_audit_entry(
        AuditEntry(
            scan_id=ctx.scan_id,
            check_id=check_id,
            action="wfs-feature-delete",
            target_url=cap.endpoint_url,
            outcome=delete_outcome,
            operator=operator,
            details={
                "type_name": type_name,
                "feature_id": feature_id,
                "error": delete_error,
            },
        )
    )

    return WfsTransactionVerification(
        added=True,
        deleted=delete_outcome is AuditOutcome.SUCCESS,
        feature_id=feature_id,
        type_name=type_name,
        error=delete_error,
    )


@dataclass(frozen=True, slots=True)
class _SchemaInfo:
    namespace: str
    geometry_property: str | None


_VERSION_2 = "2.0.0"


async def _describe_feature_type(
    ctx: Context,
    endpoint: str,
    type_name: str,
) -> _SchemaInfo | None:
    """Issue DescribeFeatureType and pull namespace + geometry property name."""
    params = {
        "SERVICE": "WFS",
        "VERSION": _VERSION_2,
        "REQUEST": "DescribeFeatureType",
        "TYPENAMES": type_name,
    }
    try:
        response = await ctx.http.get(endpoint, params=params)
    except (httpx.HTTPError, OSError):
        return None
    if response.status_code != _HTTP_OK or not response.content:
        return None
    try:
        root = Det.fromstring(response.text)
    except (Det.ParseError, ValueError):
        return None
    namespace = root.attrib.get("targetNamespace") or ""
    geometry_property: str | None = None
    for element in root.iter():
        local = element.tag.split("}", 1)[1] if "}" in element.tag else element.tag
        if local != "element":
            continue
        type_attr = element.attrib.get("type", "")
        if type_attr.startswith("gml:") or "Geometry" in type_attr or "Point" in type_attr:
            geometry_property = element.attrib.get("name")
            break
    return _SchemaInfo(namespace=namespace, geometry_property=geometry_property)


def _build_insert_xml(
    wfs_version: str,
    type_name: str,
    schema: _SchemaInfo,
    handle: str,
) -> str:
    """Construct a minimal WFS Insert with a Null Island Point."""
    prefix = "ns1"
    namespace = schema.namespace or "http://gisweep-anonymous.example"
    geom_property = schema.geometry_property or "geometry"
    local_name = type_name.split(":", 1)[1] if ":" in type_name else type_name
    if wfs_version.startswith("2"):
        return (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<wfs:Transaction service="WFS" version="2.0.0"\n'
            '  xmlns:wfs="http://www.opengis.net/wfs/2.0"\n'
            '  xmlns:gml="http://www.opengis.net/gml/3.2"\n'
            f'  xmlns:{prefix}="{namespace}">\n'
            f'  <wfs:Insert handle="{handle}">\n'
            f"    <{prefix}:{local_name}>\n"
            f"      <{prefix}:{geom_property}>\n"
            '        <gml:Point gml:id="g1" srsName="EPSG:4326">\n'
            "          <gml:pos>0 0</gml:pos>\n"
            "        </gml:Point>\n"
            f"      </{prefix}:{geom_property}>\n"
            f"    </{prefix}:{local_name}>\n"
            "  </wfs:Insert>\n"
            "</wfs:Transaction>\n"
        )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<wfs:Transaction service="WFS" version="1.1.0"\n'
        '  xmlns:wfs="http://www.opengis.net/wfs"\n'
        '  xmlns:gml="http://www.opengis.net/gml"\n'
        f'  xmlns:{prefix}="{namespace}">\n'
        f'  <wfs:Insert handle="{handle}">\n'
        f"    <{prefix}:{local_name}>\n"
        f"      <{prefix}:{geom_property}>\n"
        '        <gml:Point srsName="EPSG:4326">\n'
        "          <gml:coordinates>0,0</gml:coordinates>\n"
        "        </gml:Point>\n"
        f"      </{prefix}:{geom_property}>\n"
        f"    </{prefix}:{local_name}>\n"
        "  </wfs:Insert>\n"
        "</wfs:Transaction>\n"
    )


def _build_delete_xml(wfs_version: str, type_name: str, feature_id: str) -> str:
    if wfs_version.startswith("2"):
        return (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<wfs:Transaction service="WFS" version="2.0.0"\n'
            '  xmlns:wfs="http://www.opengis.net/wfs/2.0"\n'
            '  xmlns:fes="http://www.opengis.net/fes/2.0">\n'
            f'  <wfs:Delete typeNames="{type_name}">\n'
            "    <fes:Filter>\n"
            f'      <fes:ResourceId rid="{feature_id}"/>\n'
            "    </fes:Filter>\n"
            "  </wfs:Delete>\n"
            "</wfs:Transaction>\n"
        )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<wfs:Transaction service="WFS" version="1.1.0"\n'
        '  xmlns:wfs="http://www.opengis.net/wfs"\n'
        '  xmlns:ogc="http://www.opengis.net/ogc">\n'
        f'  <wfs:Delete typeName="{type_name}">\n'
        "    <ogc:Filter>\n"
        f'      <ogc:FeatureId fid="{feature_id}"/>\n'
        "    </ogc:Filter>\n"
        "  </wfs:Delete>\n"
        "</wfs:Transaction>\n"
    )


_RESOURCE_ID_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r'<\s*[\w:]*ResourceId\s[^>]*?\brid\s*=\s*"([^"]+)"', re.IGNORECASE),
    re.compile(r'<\s*[\w:]*FeatureId\s[^>]*?\bfid\s*=\s*"([^"]+)"', re.IGNORECASE),
    re.compile(r'\b(?:fid|featureId)\s*=\s*"([^"]+)"', re.IGNORECASE),
)


def _parse_insert_response(body: str) -> str | None:
    """Pull the first ResourceId / featureId / fid out of the Insert response."""
    if "ExceptionReport" in body or "ServiceException" in body:
        return None
    for pattern in _RESOURCE_ID_PATTERNS:
        match = pattern.search(body)
        if match:
            return match.group(1)
    return None


def _extract_xml_error(body: str) -> str | None:
    if not body:
        return None
    try:
        root = Det.fromstring(body)
    except (Det.ParseError, ValueError):
        return None
    for element in root.iter():
        local = element.tag.split("}", 1)[1] if "}" in element.tag else element.tag
        if local in {"ExceptionText", "ServiceException"}:
            text = (element.text or "").strip()
            if text:
                return text[:200]
    return None
