"""ArcGIS token helpers.

ArcGIS authenticates either with a long-lived ``?token=`` URL parameter, an
``Authorization: Bearer`` header, or a referer-bound short-lived token issued
by ``/sharing/rest/generateToken``. This module covers all three; checks read
from :class:`ArcGISToken` rather than dealing with the raw string.

Tokens are never logged unredacted; the public ``__repr__`` uses
:func:`gisweep.core.http.redact` so accidental ``print(token)`` calls are
safe.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from gisweep.core.http import redact

if TYPE_CHECKING:
    from gisweep.core.http import HttpClient

_DEFAULT_REFERER = "https://www.arcgis.com"
_DEFAULT_EXPIRATION_MINUTES = 60


@dataclass(frozen=True, slots=True)
class ArcGISToken:
    token: str
    expires_at: datetime
    portal_url: str
    referer: str

    def is_expired(self, *, skew_seconds: int = 30) -> bool:
        return datetime.now(tz=UTC) >= self.expires_at - timedelta(seconds=skew_seconds)

    def __repr__(self) -> str:
        return (
            f"ArcGISToken(token={redact(self.token)!r}, "
            f"expires_at={self.expires_at.isoformat()}, "
            f"portal_url={self.portal_url!r}, referer={self.referer!r})"
        )

    def __str__(self) -> str:
        return self.__repr__()


def sharing_token_url(portal_url: str) -> str:
    """Return the ``generateToken`` URL for a portal root."""
    return f"{portal_url.rstrip('/')}/sharing/rest/generateToken"


async def generate_token(
    http: HttpClient,
    *,
    portal_url: str,
    username: str,
    password: str,
    referer: str = _DEFAULT_REFERER,
    expiration_minutes: int = _DEFAULT_EXPIRATION_MINUTES,
) -> ArcGISToken:
    """Exchange username/password for a referer-bound ArcGIS token."""
    url = sharing_token_url(portal_url)
    payload = {
        "username": username,
        "password": password,
        "client": "referer",
        "referer": referer,
        "expiration": str(expiration_minutes),
        "f": "json",
    }
    response = await http.post(url, data=payload)
    response.raise_for_status()
    body = response.json()
    if not isinstance(body, dict) or "token" not in body:
        raise _TokenGenerationError(body)
    expires_ms = int(body.get("expires") or 0)
    expires_at = (
        datetime.fromtimestamp(expires_ms / 1000, tz=UTC)
        if expires_ms
        else datetime.now(tz=UTC) + timedelta(minutes=expiration_minutes)
    )
    return ArcGISToken(
        token=str(body["token"]),
        expires_at=expires_at,
        portal_url=portal_url.rstrip("/"),
        referer=referer,
    )


def inject_token(url: str, token: str) -> str:
    """Append ``token=...`` to ``url``'s query string, preserving other params."""
    split = urlsplit(url)
    existing = dict(parse_qsl(split.query, keep_blank_values=True))
    existing["token"] = token
    return urlunsplit((split.scheme, split.netloc, split.path, urlencode(existing), split.fragment))


def auth_headers(token: str, *, referer: str | None = None) -> dict[str, str]:
    """Header form of an ArcGIS token, equivalent to the URL-param form."""
    headers = {"X-Esri-Authorization": f"Bearer {token}"}
    if referer is not None:
        headers["Referer"] = referer
    return headers


class _TokenGenerationError(RuntimeError):
    def __init__(self, body: object) -> None:
        super().__init__(f"generateToken failed: {body!r}")
