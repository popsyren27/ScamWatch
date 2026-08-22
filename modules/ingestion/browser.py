"""
browser.py — Ingest page content (my dev notes).

Uses Playwright headless Chromium over Tor to capture DOM, requests and a
screenshot. Falls back to a plain httpx fetch if Playwright is missing.

TODO: tweak timeouts if pages with huge JS loads keep timing out on slow circuits.
Playwright is annoying to install on some CI images — that's what the fallback is for.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Optional

from pydantic import StrictStr, validate_call

from config import ARTIFACT_DIR, NAV_TIMEOUT_MS, PAGE_TIMEOUT_MS, TOR_PROXY_URL, USER_AGENT
from models import IngestedPage
from modules.logging_setup import get_logger
from modules.proxy.tor_manager import build_client

log = get_logger("ingestion.browser")

_NETWORK_IDLE_GRACE_MS = 5_000


def _screenshot_path_for(target_url: str) -> Path:
    artifact_dir = Path(ARTIFACT_DIR)
    artifact_dir.mkdir(parents=True, exist_ok=True)

    slug = re.sub(r"[^A-Za-z0-9._-]", "_", target_url)
    slug = slug[:120] or "target"

    return artifact_dir / f"{slug}.png"


async def _fallback_httpx_fetch(target_url: str, direct: bool = False) -> IngestedPage:
    """Static fetch used when Playwright is unavailable or fails. No JS, no screenshot."""
    log.info("static fetch for %s (direct=%s)", target_url, direct)
    client = build_client(direct=direct)
    try:
        resp = await client.get(target_url)
        headers = dict(resp.headers)
        return IngestedPage(
            final_url=str(resp.url),
            http_status=resp.status_code,
            response_headers=headers,
            dom_html=resp.text or "",
            network_requests=[],
            screenshot_path=None,
            rendered=False,
        )
    finally:
        try:
            await client.aclose()
        except Exception as exc:
            log.debug("client.aclose() failed, ignoring: %s", exc)


async def _navigate(page: Any, target_url: str) -> Optional[Any]:
    """Go to target_url. Nav errors are swallowed — partial render beats none."""
    response: Optional[Any] = None
    try:
        response = await page.goto(target_url, timeout=NAV_TIMEOUT_MS, wait_until="domcontentloaded")
        try:
            # bounded wait for late XHR past DOMContentLoaded — plenty of
            # pages never go fully idle, that's expected
            await page.wait_for_load_state("networkidle", timeout=_NETWORK_IDLE_GRACE_MS)
        except Exception:
            pass
    except Exception as exc:
        log.warning("navigation incomplete for %s (continuing): %s", target_url, exc)
    return response


async def _extract_rendered_bundle(
    page: Any, response: Optional[Any], target_url: str, network_requests: list[str], shot_path: Path,
) -> IngestedPage:
    # page can be half-torn-down after a bad navigation, so each read below
    # is independent and allowed to fail on its own
    status = response.status if response is not None else 0
    status = status or 0

    dom_html = ""
    try:
        dom_html = await page.content()
    except Exception as exc:
        log.debug("page.content() failed for %s: %s", target_url, exc)

    final_url = target_url
    try:
        final_url = page.url
    except Exception as exc:
        log.debug("page.url failed for %s: %s", target_url, exc)

    headers: dict = {}
    if response is not None:
        try:
            headers = dict(response.headers)
        except Exception as exc:
            log.debug("response.headers failed for %s: %s", target_url, exc)

    try:
        await page.screenshot(path=str(shot_path), full_page=True)
    except Exception as exc:
        log.debug("screenshot failed for %s: %s", target_url, exc)

    screenshot_exists = shot_path.exists()
    log.info("%s status=%s dom_bytes=%s screenshot=%s", final_url, status, len(dom_html), screenshot_exists)

    return IngestedPage(
        final_url=final_url,
        http_status=int(status),
        response_headers=headers,
        dom_html=dom_html,
        network_requests=network_requests,
        screenshot_path=str(shot_path) if screenshot_exists else None,
        rendered=True,
    )


async def _teardown_playwright(playwright: Any, browser: Any, context: Any) -> None:
    if context is not None:
        try:
            await context.close()
        except Exception as exc:
            log.debug("context.close() failed: %s", exc)
    if browser is not None:
        try:
            await browser.close()
        except Exception as exc:
            log.debug("browser.close() failed: %s", exc)
    if playwright is not None:
        try:
            await playwright.stop()
        except Exception as exc:
            log.debug("playwright.stop() failed: %s", exc)


async def _render_with_playwright(target_url: str, direct: bool) -> IngestedPage:
    shot_path = _screenshot_path_for(target_url)
    network_requests: list[str] = []

    from playwright.async_api import async_playwright  # type: ignore

    playwright = None
    browser = None
    context = None
    try:
        playwright = await async_playwright().start()

        launch_kwargs: dict[str, Any] = {
            "headless": True,
            "args": ["--no-sandbox", "--disable-dev-shm-usage"],
        }
        # proxy goes on the browser itself so sub-resources and XHR are
        # forced through Tor too — 'direct' is the only off-Tor path
        if not direct:
            launch_kwargs["proxy"] = {"server": TOR_PROXY_URL}
        browser = await playwright.chromium.launch(**launch_kwargs)

        context = await browser.new_context(
            user_agent=USER_AGENT,
            ignore_https_errors=True,  # scam sites often have broken TLS
        )
        context.set_default_timeout(PAGE_TIMEOUT_MS)
        page = await context.new_page()

        def on_request(req: Any) -> None:
            network_requests.append(f"{req.method} {req.url}")

        page.on("request", on_request)

        response = await _navigate(page, target_url)
        return await _extract_rendered_bundle(page, response, target_url, network_requests, shot_path)
    except Exception as exc:
        log.error("browser ingestion failed for %s: %s", target_url, exc)
        try:
            return await _fallback_httpx_fetch(target_url, direct=direct)
        except Exception as fallback_exc:
            log.error("fallback fetch also failed for %s: %s", target_url, fallback_exc)
            return IngestedPage(final_url=target_url, http_status=0, rendered=False)
    finally:
        await _teardown_playwright(playwright, browser, context)


@validate_call
async def ingest_target(target_url: StrictStr, direct: bool = False) -> IngestedPage:
    """Render target_url (through Tor, or direct for loopback) into an IngestedPage.

    Never raises for ordinary network/render failures — returns a best-effort
    bundle and logs the cause. direct=True is only used by the pipeline for
    loopback targets.
    """
    try:
        import playwright.async_api  # noqa: F401
    except ImportError:
        log.warning("Playwright not installed, using static httpx fallback")
        try:
            return await _fallback_httpx_fetch(target_url, direct=direct)
        except Exception as exc:
            log.error("fallback fetch failed for %s: %s", target_url, exc)
            return IngestedPage(final_url=target_url, http_status=0, dom_html="", rendered=False)

    return await _render_with_playwright(target_url, direct)