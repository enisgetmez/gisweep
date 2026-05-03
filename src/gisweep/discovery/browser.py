"""Playwright-based web crawler.

Loads a single URL in headless Chromium, captures the network request log,
sniffs the response body of script and document responses, and reads the
canonical library globals via ``page.evaluate``. The result is a
:class:`WebDiscoveryResult` that the WEB-* checks consume — the crawler
itself emits no findings.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from gisweep.discovery.library_detect import (
    JS_GLOBAL_PROBE,
    DetectedLibrary,
    detect_from_globals,
    detect_from_url,
    merge,
)

if TYPE_CHECKING:
    from playwright.async_api import Page


@dataclass(frozen=True, slots=True)
class CapturedRequest:
    url: str
    method: str
    resource_type: str
    response_status: int | None
    response_headers: tuple[tuple[str, str], ...]


@dataclass(slots=True)
class CapturedResponseBody:
    url: str
    resource_type: str
    body: str


@dataclass(slots=True)
class WebDiscoveryResult:
    page_url: str
    final_url: str
    requests: list[CapturedRequest] = field(default_factory=list)
    libraries: list[DetectedLibrary] = field(default_factory=list)
    bodies: list[CapturedResponseBody] = field(default_factory=list)
    page_html: str = ""
    iframes: list[dict[str, str]] = field(default_factory=list)
    scripts: list[dict[str, str]] = field(default_factory=list)


_SNIFFABLE_TYPES: frozenset[str] = frozenset({"document", "script", "xhr", "fetch", "stylesheet"})
_DEFAULT_NAVIGATION_TIMEOUT_MS = 30_000
_DEFAULT_NETWORK_IDLE_TIMEOUT_MS = 8_000
_MAX_BODY_BYTES = 1_000_000  # 1 MB per response


class BrowserCrawler:
    def __init__(
        self,
        *,
        headless: bool = True,
        navigation_timeout_ms: int = _DEFAULT_NAVIGATION_TIMEOUT_MS,
        network_idle_timeout_ms: int = _DEFAULT_NETWORK_IDLE_TIMEOUT_MS,
        user_agent: str | None = None,
    ) -> None:
        self._headless = headless
        self._navigation_timeout_ms = navigation_timeout_ms
        self._network_idle_timeout_ms = network_idle_timeout_ms
        self._user_agent = user_agent

    async def crawl(self, url: str) -> WebDiscoveryResult:
        from playwright.async_api import async_playwright  # noqa: PLC0415

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=self._headless)
            try:
                context = await browser.new_context(user_agent=self._user_agent)
                page = await context.new_page()
                page.set_default_navigation_timeout(self._navigation_timeout_ms)
                result = WebDiscoveryResult(page_url=url, final_url=url)
                await self._instrument(page, result)
                try:
                    await page.goto(url)
                except Exception as exc:
                    result.bodies.append(
                        CapturedResponseBody(url=url, resource_type="error", body=str(exc))
                    )
                    return result
                with contextlib.suppress(Exception):
                    await page.wait_for_load_state(
                        "networkidle", timeout=self._network_idle_timeout_ms
                    )

                result.final_url = page.url
                result.page_html = await page.content()
                result.scripts = await page.evaluate(_SCRIPT_INVENTORY_JS)
                result.iframes = await page.evaluate(_IFRAME_INVENTORY_JS)
                try:
                    probe = await page.evaluate(JS_GLOBAL_PROBE)
                except Exception:
                    probe = {}
                if isinstance(probe, dict):
                    result.libraries.extend(detect_from_globals(probe))
                for req in result.requests:
                    hit = detect_from_url(req.url)
                    if hit is not None:
                        result.libraries.append(hit)
                result.libraries = merge(result.libraries)
                return result
            finally:
                await browser.close()

    async def _instrument(self, page: Page, result: WebDiscoveryResult) -> None:
        async def _on_response(response: object) -> None:
            try:
                request = response.request  # type: ignore[attr-defined]
            except AttributeError:
                return
            resource_type = request.resource_type
            captured = CapturedRequest(
                url=request.url,
                method=request.method,
                resource_type=resource_type,
                response_status=response.status,  # type: ignore[attr-defined]
                response_headers=tuple(response.headers.items()),  # type: ignore[attr-defined]
            )
            result.requests.append(captured)
            if resource_type in _SNIFFABLE_TYPES:
                try:
                    body_bytes = await response.body()  # type: ignore[attr-defined]
                except Exception:
                    return
                if not body_bytes or len(body_bytes) > _MAX_BODY_BYTES:
                    return
                try:
                    text = body_bytes.decode("utf-8", errors="replace")
                except Exception:
                    return
                result.bodies.append(
                    CapturedResponseBody(
                        url=request.url,
                        resource_type=resource_type,
                        body=text,
                    )
                )

        page.on("response", _on_response)


_SCRIPT_INVENTORY_JS = """() => Array.from(document.querySelectorAll('script')).map(s => ({
    src: s.src || '',
    integrity: s.integrity || '',
    crossorigin: s.crossOrigin || '',
}))
"""

_IFRAME_INVENTORY_JS = """() => Array.from(document.querySelectorAll('iframe')).map(f => ({
    src: f.src || '',
    sandbox: f.getAttribute('sandbox') || '',
    referrerpolicy: f.getAttribute('referrerpolicy') || '',
}))
"""
