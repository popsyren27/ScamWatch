"""
browser.py — Ingest page content (my dev notes).

Uses Playwright headless Chromium over Tor to capture DOM, requests and a
screenshot. Falls back to a plain httpx fetch if Playwright is missing.

Playwright is annoying to install on some CI images — that's what the fallback is for.
"""

from __future__ import annotations

import asyncio
import datetime as _dt
import hashlib
import json
import re
import uuid
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

from httpx import HTTPError
from pydantic import StrictStr, validate_call

from config import (
    ARTIFACT_DIR, NAV_RETRY_SETTLE_MS,
    NAV_RETRY_TIMEOUT_MS, NAV_TIMEOUT_MS, PAGE_TIMEOUT_MS, SITE_ARCHIVE_DIR,
    TOR_PROXY_URL, USER_AGENT,
)
from models import IngestedPage
from modules.logging_setup import get_logger
from modules.proxy.tor_manager import build_client

log = get_logger("ingestion.browser")

_NETWORK_IDLE_GRACE_MS = 5_000
_MAX_NETWORK_REQUESTS = 2_000

# Anti-bot interstitials (Bunny Shield, Cloudflare, etc.) serve a JS challenge
# that must run before the real page appears. Headless Chromium CAN pass these
# if we just wait; they're proof-of-work, not CAPTCHAs.
_CHALLENGE_MARKERS = (
    "bunny-shield", "shield-challenge", "cf-chl", "cf-browser-verification",
    "just a moment", "checking your browser", "attention required",
    "establishing a secure connection", "ddos protection by",
    # AWS WAF (site123 uses it behind BunnyCDN): token endpoint + goku props
    "awswaf", "token.awswaf.com", "goku_props", "window.gokuprops",
)
_CHALLENGE_MAX_WAIT_S = 60
_CHALLENGE_POLL_INTERVAL_S = 2.0

# Chromium's internal failure pages — not real content, must not count as loaded.
_BROWSER_ERROR_MARKERS = ("chrome-error://", "data:text/html,chromewebdata")
_MIN_REAL_DOM_BYTES = 500


def _looks_like_challenge(dom_html: str) -> bool:
    low = (dom_html or "").lower()
    return any(marker in low for marker in _CHALLENGE_MARKERS)


def _is_usable_dom(final_url: str, dom_html: str) -> bool:
    if any(marker in (final_url or "") for marker in _BROWSER_ERROR_MARKERS):
        return False
    return len((dom_html or "").strip()) >= _MIN_REAL_DOM_BYTES


def _capture_name(target_url: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]", "_", target_url)[:80] or "target"
    digest = hashlib.sha256(target_url.encode()).hexdigest()[:12]
    return f"{slug}-{digest}-{uuid.uuid4().hex[:12]}"


def _screenshot_path_for(capture_name: str) -> Path:
    artifact_dir = Path(ARTIFACT_DIR)
    artifact_dir.mkdir(parents=True, exist_ok=True)
    return artifact_dir / f"{capture_name}.png"


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
        except (HTTPError, OSError) as exc:
            log.debug("client.aclose() failed: %s", exc)


async def _navigate(page: Any, target_url: str) -> Optional[Any]:
    from playwright.async_api import Error as PlaywrightError
    from playwright.async_api import TimeoutError as PlaywrightTimeoutError

    response: Optional[Any] = None
    try:
        response = await page.goto(target_url, timeout=NAV_TIMEOUT_MS, wait_until="domcontentloaded")
        try:
            await page.wait_for_load_state("networkidle", timeout=_NETWORK_IDLE_GRACE_MS)
        except PlaywrightTimeoutError:
            pass
    except (PlaywrightError, PlaywrightTimeoutError) as exc:
        log.warning("navigation incomplete for %s (continuing): %s", target_url, exc)
    return response


async def _navigate_slow(page: Any, target_url: str) -> Optional[Any]:
    from playwright.async_api import Error as PlaywrightError
    from playwright.async_api import TimeoutError as PlaywrightTimeoutError

    response: Optional[Any] = None
    try:
        response = await page.goto(target_url, timeout=NAV_RETRY_TIMEOUT_MS,
                                   wait_until="domcontentloaded")
    except (PlaywrightError, PlaywrightTimeoutError) as exc:
        log.warning("slow navigation also incomplete for %s: %s", target_url, exc)
    try:
        await page.wait_for_load_state("networkidle", timeout=NAV_RETRY_SETTLE_MS)
    except PlaywrightTimeoutError:
        pass
    return response


async def _resolve_challenge(page: Any) -> bool:
    """Wait until the page shows a real DOM, not an anti-bot interstitial.

    Shields often pass through several stages (challenge -> intermediate
    redirect page -> real site), so 'not a challenge anymore' isn't enough —
    we wait for substantial real content.
    """
    from playwright.async_api import Error as PlaywrightError
    from playwright.async_api import TimeoutError as PlaywrightTimeoutError

    deadline = _dt.datetime.now() + _dt.timedelta(seconds=_CHALLENGE_MAX_WAIT_S)
    reloaded = False
    while _dt.datetime.now() < deadline:
        await asyncio.sleep(_CHALLENGE_POLL_INTERVAL_S)
        try:
            dom = await page.content()
            url = page.url
        except PlaywrightError:
            continue
        if not _looks_like_challenge(dom) and _is_usable_dom(url, dom):
            log.info("anti-bot challenge cleared (dom_bytes=%s)", len(dom))
            return True
        # some challenges need one reload after solving their PoW; don't
        # reload-loop — one reload is usually enough for the intermediate stage
        if not reloaded and _looks_like_challenge(dom):
            try:
                await page.reload(wait_until="domcontentloaded", timeout=NAV_TIMEOUT_MS)
                reloaded = True
            except (PlaywrightError, PlaywrightTimeoutError) as exc:
                log.debug("challenge reload failed (will retry): %s", exc)
    return False


def _archive_dir_for(capture_name: str) -> Path:
    out = Path(SITE_ARCHIVE_DIR) / capture_name
    out.mkdir(parents=True, exist_ok=True)
    return out


def _archive_page(capture_name: str, target_url: str, dom_html: str,
                  network_requests: list[str], http_status: int) -> Optional[str]:
    try:
        out = _archive_dir_for(capture_name)
        (out / "dom.html").write_text(dom_html or "", encoding="utf-8")
        (out / "requests.log").write_text("\n".join(network_requests), encoding="utf-8")
        (out / "meta.json").write_text(
            json.dumps({"url": target_url, "http_status": http_status,
                        "dom_bytes": len(dom_html or ""),
                        "captured_utc": _dt.datetime.now(_dt.timezone.utc).isoformat()},
                       indent=2),
            encoding="utf-8")
        log.info("Site archive written to %s", out)
        return str(out)
    except OSError as exc:
        log.warning("Could not archive %s: %s", target_url, exc)
        return None


async def _extract_rendered_bundle(
    page: Any, response: Optional[Any], target_url: str, network_requests: list[str],
    shot_path: Path, observed_status: int = 0,
) -> IngestedPage:
    from playwright.async_api import Error as PlaywrightError

    status = response.status if response is not None else observed_status

    dom_html = ""
    try:
        dom_html = await page.content()
    except PlaywrightError as exc:
        log.debug("page.content() failed for %s: %s", target_url, exc)

    final_url = target_url
    try:
        final_url = page.url
    except PlaywrightError as exc:
        log.debug("page.url failed for %s: %s", target_url, exc)

    if not status and _is_usable_dom(final_url, dom_html):
        status = 200

    headers: dict = {}
    if response is not None:
        try:
            headers = dict(response.headers)
        except PlaywrightError as exc:
            log.debug("response.headers failed for %s: %s", target_url, exc)

    try:
        await page.screenshot(path=str(shot_path), full_page=True)
    except PlaywrightError as exc:
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
    from playwright.async_api import Error as PlaywrightError

    if context is not None:
        try:
            await context.close()
        except PlaywrightError as exc:
            log.debug("context.close() failed: %s", exc)
    if browser is not None:
        try:
            await browser.close()
        except PlaywrightError as exc:
            log.debug("browser.close() failed: %s", exc)
    if playwright is not None:
        try:
            await playwright.stop()
        except PlaywrightError as exc:
            log.debug("playwright.stop() failed: %s", exc)


async def _render_with_playwright(target_url: str, direct: bool) -> IngestedPage:
    capture_name = _capture_name(target_url)
    shot_path = _screenshot_path_for(capture_name)
    network_requests: list[str] = []
    requests_truncated = False

    from playwright.async_api import Error as PlaywrightError
    from playwright.async_api import async_playwright

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
        # forced through Tor too — 'direct' is the only off-Tor path.
        # Chromium does NOT understand 'socks5h://' (that's a curl/httpx
        # extension); plain 'socks5://' is what it accepts, and Chromium
        # resolves DNS through the SOCKS proxy anyway.
        if not direct:
            launch_kwargs["proxy"] = {"server": TOR_PROXY_URL.replace("socks5h://", "socks5://")}
        browser = await playwright.chromium.launch(**launch_kwargs)

        context = await browser.new_context(
            user_agent=USER_AGENT,
            ignore_https_errors=True,  # scam sites often have broken TLS
        )
        context.set_default_timeout(PAGE_TIMEOUT_MS)
        page = await context.new_page()

        def on_request(req: Any) -> None:
            nonlocal requests_truncated
            if len(network_requests) < _MAX_NETWORK_REQUESTS:
                network_requests.append(f"{req.method} {req.url}")
            elif not requests_truncated:
                log.warning("Request capture limit reached for %s", target_url)
                requests_truncated = True

        def on_response(resp: Any) -> None:
            try:
                request = resp.request
                if request.is_navigation_request() and request.frame == page.main_frame:
                    _main_doc_response[0] = resp
            except PlaywrightError:
                pass

        _main_doc_response: list[Any | None] = [None]
        page.on("request", on_request)
        page.on("response", on_response)

        response = await _navigate(page, target_url)

        got_content = response is not None or (page.url != "about:blank")
        if not got_content:
            log.warning("first render produced nothing for %s — retrying with a long timeout", target_url)
            response = await _navigate_slow(page, target_url)
            got_content = response is not None or (page.url != "about:blank")

        if not got_content:
            log.warning("rendered attempts failed for %s — trying static fetch", target_url)
            static_page = await _fallback_httpx_fetch(target_url, direct=direct)
            if (static_page.dom_html or "").strip():
                await asyncio.to_thread(
                    _archive_page,
                    capture_name,
                    target_url,
                    static_page.dom_html,
                    [],
                    static_page.http_status,
                )
                return static_page
            return static_page

        bundle = await _extract_rendered_bundle(page, _main_doc_response[0] or response, target_url,
                                                network_requests, shot_path,
                                                observed_status=0)

        # Anti-bot interstitials (Bunny Shield 403, Cloudflare 503, ...) serve
        # a JS challenge that a real browser clears automatically. Wait until
        # the REAL page renders — shields pass through intermediate pages on
        # the way, so "not a challenge" alone isn't success.
        needs_wait = (_looks_like_challenge(bundle.dom_html)
                      or not _is_usable_dom(bundle.final_url, bundle.dom_html))
        if needs_wait:
            log.info("anti-bot challenge / thin page detected for %s — waiting for the real page", target_url)
            if await _resolve_challenge(page):
                bundle = await _extract_rendered_bundle(
                    page, _main_doc_response[0], target_url, network_requests, shot_path)
                if not bundle.http_status or bundle.http_status in (403, 202):
                    bundle.http_status = 200  # challenge passed; body is the real page
            else:
                log.warning("page never rendered real content within %ss",
                            _CHALLENGE_MAX_WAIT_S)

        await asyncio.to_thread(
            _archive_page,
            capture_name,
            target_url,
            bundle.dom_html,
            network_requests,
            bundle.http_status,
        )
        return bundle
    finally:
        await _teardown_playwright(playwright, browser, context)


@validate_call
async def ingest_target(target_url: StrictStr, direct: bool = False) -> IngestedPage:
    parsed = urlparse(target_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("Target URL must use http or https and include a host.")

    try:
        from playwright.async_api import Error as PlaywrightError
    except ImportError:
        log.warning("Playwright not installed, using static httpx fallback")
        return await _fallback_httpx_fetch(target_url, direct=direct)

    try:
        return await _render_with_playwright(target_url, direct)
    except (PlaywrightError, OSError) as exc:
        log.warning("Browser ingestion failed for %s: %s; using static fetch.", target_url, exc)
        return await _fallback_httpx_fetch(target_url, direct=direct)
