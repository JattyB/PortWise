from __future__ import annotations

from pathlib import Path


def write_pdf_report(html_path: Path, output_path: Path) -> Path:
    """Render the existing self-contained HTML report through managed Chromium."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise RuntimeError("PDF output requires portwise[screenshots] and managed Chromium.") from exc
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        try:
            page = browser.new_page()
            page.goto(html_path.resolve().as_uri(), wait_until="load")
            page.emulate_media(media="screen")
            page.pdf(path=str(output_path), format="A4", print_background=True, prefer_css_page_size=True)
        finally:
            browser.close()
    return output_path
