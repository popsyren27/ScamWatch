import asyncio

from modules.ingestion import browser


def test_remote_browser_failure_keeps_static_fetch_on_tor(monkeypatch):
    calls = []

    async def fail_render(url, direct):
        raise OSError("browser unavailable")

    async def fetch(url, direct):
        calls.append((url, direct))
        return browser.IngestedPage(final_url=url, http_status=200)

    monkeypatch.setattr(browser, "_render_with_playwright", fail_render)
    monkeypatch.setattr(browser, "_fallback_httpx_fetch", fetch)

    page = asyncio.run(browser.ingest_target("https://example.test", direct=False))

    assert page.http_status == 200
    assert calls == [("https://example.test", False)]
