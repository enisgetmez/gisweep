"""Unit tests for the ArcGIS auth helpers."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest
import respx
from httpx import Response

from gisweep.auth.arcgis_token import (
    ArcGISToken,
    auth_headers,
    generate_token,
    inject_token,
    sharing_token_url,
)
from gisweep.core.http import HttpClient
from gisweep.core.options import ScanOptions

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

PORTAL = "https://portal.example/portal"


@pytest.fixture
async def http() -> AsyncIterator[HttpClient]:
    client = HttpClient(ScanOptions())
    yield client
    await client.aclose()


def test_sharing_token_url_appends_endpoint() -> None:
    assert sharing_token_url(PORTAL) == f"{PORTAL}/sharing/rest/generateToken"
    assert sharing_token_url(PORTAL + "/") == f"{PORTAL}/sharing/rest/generateToken"


def test_inject_token_preserves_other_query_params() -> None:
    url = "https://x.example/arcgis/rest/services?f=json&where=1=1"
    out = inject_token(url, "tok")
    assert "token=tok" in out
    assert "f=json" in out
    assert "where=1%3D1" in out or "where=1=1" in out


def test_auth_headers_sets_x_esri_authorization() -> None:
    headers = auth_headers("tok-abcd")
    assert headers == {"X-Esri-Authorization": "Bearer tok-abcd"}
    headers2 = auth_headers("tok-abcd", referer="https://app.example")
    assert headers2["Referer"] == "https://app.example"


@respx.mock
async def test_generate_token_parses_response(http: HttpClient) -> None:
    expires_at = int((datetime.now(tz=UTC) + timedelta(minutes=60)).timestamp() * 1000)
    respx.post(sharing_token_url(PORTAL)).mock(
        return_value=Response(200, json={"token": "TOK-1234", "expires": expires_at})
    )
    tok = await generate_token(
        http,
        portal_url=PORTAL,
        username="alice",
        password="secret",
        referer="https://app.example",
    )
    assert tok.token == "TOK-1234"
    assert tok.referer == "https://app.example"
    assert tok.is_expired() is False


@respx.mock
async def test_generate_token_raises_on_error_payload(http: HttpClient) -> None:
    respx.post(sharing_token_url(PORTAL)).mock(
        return_value=Response(200, json={"error": {"code": 400, "message": "Invalid credentials"}})
    )
    with pytest.raises(RuntimeError, match="generateToken failed"):
        await generate_token(http, portal_url=PORTAL, username="x", password="y")


def test_arcgis_token_repr_redacts_token_string() -> None:
    tok = ArcGISToken(
        token="TOK-SECRET-VALUE-1234",
        expires_at=datetime(2026, 5, 3, tzinfo=UTC),
        portal_url=PORTAL,
        referer="r",
    )
    rendered = repr(tok)
    assert "SECRET" not in rendered
    assert "1234" in rendered  # last 4 chars surface as fingerprint
    assert "***" in rendered
