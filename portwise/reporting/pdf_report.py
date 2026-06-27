from __future__ import annotations

from pathlib import Path


def write_pdf_report(html_path: Path, output_path: Path) -> Path:
    """Render the existing self-contained HTML report through managed Chromium."""
    try:
        from playwright.async_api import async_playwright
    except ImportError as exc:
        raise RuntimeError("PDF output requires portwise[screenshots] and managed Chromium.") from exc
    from portwise.intelligence.screenshots import _run_async

    output_path.parent.mkdir(parents=True, exist_ok=True)

    async def render() -> None:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=True)
            try:
                page = await browser.new_page()
                await page.goto(html_path.resolve().as_uri(), wait_until="load")
                await page.emulate_media(media="screen")
                await page.pdf(path=str(output_path), format="A4", print_background=True, prefer_css_page_size=True)
            finally:
                await browser.close()

    _run_async(render())
    return output_path
