"""CVE database loader and version-range matcher.

The bundled :file:`gisweep/data/cve_db.json` is keyed by ``vendor:product``
(matching the CPE 2.3 component) and lists every CVE record that affects one
or more versions of that product. Records are pulled from NIST NVD by
:mod:`scripts.refresh_cve_db` and stored verbatim where possible — so a
``cve_id`` always corresponds to a real, public advisory.
"""

from gisweep.cve.db import (
    CveRecord,
    CveSeverity,
    VersionRange,
    get_cve_database,
    load_database_from_path,
    matches_range,
)

__all__ = [
    "CveRecord",
    "CveSeverity",
    "VersionRange",
    "get_cve_database",
    "load_database_from_path",
    "matches_range",
]
