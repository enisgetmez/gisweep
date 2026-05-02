"""Shared httpx async client.

Wraps ``httpx.AsyncClient`` with:
- a global ``asyncio.Semaphore`` enforcing ``max_concurrency``
- per-host minimum interval enforcement when ``rate_limit`` is set
- consistent User-Agent / proxy / timeout / TLS handling
- small redaction helper for surfacing request/response into ``Evidence``
"""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING, Any, Self
from urllib.parse import urlsplit

import httpx

if TYPE_CHECKING:
    from types import TracebackType

    from gisweep.core.options import ScanOptions

_SAFE_RESPONSE_HEADERS: frozenset[str] = frozenset(
    {
        "content-type",
        "content-length",
        "server",
        "x-powered-by",
        "access-control-allow-origin",
        "access-control-allow-credentials",
        "access-control-allow-methods",
        "access-control-allow-headers",
        "strict-transport-security",
        "x-frame-options",
        "x-content-type-options",
        "content-security-policy",
        "referrer-policy",
    }
)

_SECRET_HEADERS: frozenset[str] = frozenset(
    {
        "authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
        "proxy-authorization",
    }
)


class HttpClient:
    def __init__(self, options: ScanOptions) -> None:
        self._options = options
        self._client = httpx.AsyncClient(
            timeout=options.timeout,
            proxy=options.proxy,
            headers={"User-Agent": options.user_agent},
            follow_redirects=True,
            verify=options.verify_tls,
        )
        self._semaphore = asyncio.Semaphore(options.max_concurrency)
        self._host_locks: dict[str, asyncio.Lock] = {}
        self._last_request: dict[str, float] = {}
        self._table_lock = asyncio.Lock()

    async def request(
        self,
        method: str,
        url: str,
        **kwargs: Any,
    ) -> httpx.Response:
        host = urlsplit(url).netloc
        await self._gate(host)
        async with self._semaphore:
            return await self._client.request(method, url, **kwargs)

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("POST", url, **kwargs)

    async def head(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("HEAD", url, **kwargs)

    async def options(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("OPTIONS", url, **kwargs)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def _gate(self, host: str) -> None:
        if self._options.rate_limit is None or self._options.rate_limit <= 0:
            return
        async with self._table_lock:
            lock = self._host_locks.setdefault(host, asyncio.Lock())
        async with lock:
            min_interval = 1.0 / self._options.rate_limit
            last = self._last_request.get(host, 0.0)
            now = time.monotonic()
            wait = min_interval - (now - last)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_request[host] = time.monotonic()


def safe_response_headers(headers: httpx.Headers) -> dict[str, str]:
    """Return only headers safe to surface as Evidence (no secrets)."""
    return {k: v for k, v in headers.items() if k.lower() in _SAFE_RESPONSE_HEADERS}


def redact_request_headers(headers: dict[str, str]) -> dict[str, str]:
    """Replace secret-bearing headers with a redacted marker."""
    out: dict[str, str] = {}
    for key, value in headers.items():
        if key.lower() in _SECRET_HEADERS:
            out[key] = redact(value)
        else:
            out[key] = value
    return out


_REDACT_FINGERPRINT_MIN_LEN = 8


def redact(value: str) -> str:
    """Reduce a token-shaped string to a safe fingerprint."""
    if not value:
        return value
    cleaned = value.removeprefix("Bearer ").removeprefix("bearer ").strip()
    tail = cleaned[-4:] if len(cleaned) >= _REDACT_FINGERPRINT_MIN_LEN else ""
    return f"***{tail}" if tail else "***"
