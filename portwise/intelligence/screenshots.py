"""Optional screenshot evidence via Playwright.

The screenshot engine is an optional extra. When ``portwise[screenshots]`` is
installed with Playwright's managed Chromium browser, PortWise screenshots each
discovered web service and attaches the image path to relevant findings and the
POC bundle. Without the extra it skips cleanly and records a note.
"""
from __future__ import annotations

import asyncio
import importlib.util
import os
import re
import sys
import threading
from collections.abc import Awaitable, Callable
from typing import Any

from portwise.core.models import Confidence, Evidence, Finding, FindingCategory, Severity
from portwise.intelligence.web_engines import _target_to_dict, _target_url

ScreenshotCapturer = Callable[[str, str, dict[str, Any]], Awaitable[None]]


def _screenshots_cfg(config: dict[str, Any]) -> dict[str, Any]:
    shots = config.get("screenshots", {}) if isinstance(config.get("screenshots"), dict) else {}
    return shots if isinstance(shots, dict) else {}


def _playwright_cfg(config: dict[str, Any]) -> dict[str, Any]:
    shots = _screenshots_cfg(config)
    section = shots.get("playwright", {})
    return section if isinstance(section, dict) else {}


def _slug(url: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]+", "_", url).strip("_")[:120] or "screenshot"


def _playwright_available() -> bool:
    try:
        return importlib.util.find_spec("playwright.async_api") is not None
    except ModuleNotFoundError:
        return False


def _run_async(coro: Awaitable[None]) -> None:
    if sys.platform == "win32":
        # curl_cffi uses the selector policy on Windows, while Playwright needs
        # subprocess support from a Proactor loop. Isolate browser capture in a
        # dedicated Proactor thread instead of changing the scan's shared loop.
        error: list[BaseException] = []

        def runner() -> None:
            loop = asyncio.ProactorEventLoop()
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(coro)
            except BaseException as exc:
                error.append(exc)
            finally:
                loop.run_until_complete(loop.shutdown_asyncgens())
                loop.close()

        thread = threading.Thread(target=runner, name="portwise-playwright", daemon=True)
        thread.start()
        thread.join()
        if error:
            raise error[0]
        return
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        asyncio.run(coro)
        return
    close = getattr(coro, "close", None)
    if callable(close):
        close()
    raise RuntimeError("Playwright screenshot capture must run from a synchronous scan context.")


async def _capture_with_playwright(url: str, dest: str, cfg: dict[str, Any]) -> None:
    from playwright.async_api import async_playwright

    timeout_ms = int(float(cfg.get("timeout", 30)) * 1000)
    wait_until = str(cfg.get("wait_until", "domcontentloaded"))
    viewport = cfg.get("viewport") if isinstance(cfg.get("viewport"), dict) else {}
    width = int(viewport.get("width", cfg.get("width", 1366)))
    height = int(viewport.get("height", cfg.get("height", 768)))
    full_page = bool(cfg.get("full_page", True))
    user_agent = cfg.get("user_agent")

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=True)
        try:
            context_kwargs: dict[str, Any] = {
                "ignore_https_errors": bool(cfg.get("ignore_https_errors", True)),
                "viewport": {"width": width, "height": height},
            }
            if user_agent:
                context_kwargs["user_agent"] = str(user_agent)
            context = await browser.new_context(**context_kwargs)
            try:
                page = await context.new_page()
                await page.goto(url, wait_until=wait_until, timeout=timeout_ms)
                await page.screenshot(path=dest, full_page=full_page)
            finally:
                await context.close()
        finally:
            await browser.close()


def capture_screenshot(
    target: dict[str, Any],
    out_dir: str,
    config: dict[str, Any],
    *,
    capturer: ScreenshotCapturer | None = None,
) -> tuple[str | None, str]:
    """Screenshot one web target. Returns (image_path_or_None, status_note)."""
    shots_cfg = _screenshots_cfg(config)
    if not bool(shots_cfg.get("enabled", True)):
        return None, "screenshots: disabled by config"

    cfg = _playwright_cfg(config)
    if not bool(cfg.get("enabled", True)):
        return None, "playwright: disabled by config"
    if capturer is None and not _playwright_available():
        return None, "playwright: not installed; skipped - install portwise[screenshots]"

    url = _target_url(target)
    os.makedirs(out_dir, exist_ok=True)
    dest = os.path.join(out_dir, f"{_slug(url)}.png")
    try:
        _run_async((capturer or _capture_with_playwright)(url, dest, cfg))
    except Exception as exc:
        lines = str(exc).splitlines()
        message = lines[0] if lines else exc.__class__.__name__
        if "Executable doesn't exist" in message or "playwright install" in message:
            return None, "playwright: Chromium browser is not installed; skipped - run playwright install chromium"
        return None, f"playwright: screenshot failed for {url}: {message}"
    if os.path.isfile(dest) and os.path.getsize(dest) > 0:
        return dest, f"playwright: captured {url}"
    return None, f"playwright: ran but produced no screenshot for {url}"


def run_screenshots(
    web_targets: list[Any],
    config: dict[str, Any],
    *,
    out_dir: str,
    existing_findings: list[Finding] | None = None,
    capturer: ScreenshotCapturer | None = None,
) -> tuple[list[Finding], list[str]]:
    """Screenshot each unique web target and attach paths to matching findings."""
    shots_cfg = _screenshots_cfg(config)
    if not bool(shots_cfg.get("enabled", True)):
        return [], ["screenshots: disabled by config"]

    by_endpoint: dict[tuple[str, int], list[Finding]] = {}
    for finding in existing_findings or []:
        by_endpoint.setdefault((str(finding.asset), int(finding.port or 0)), []).append(finding)

    findings: list[Finding] = []
    notes: list[str] = []
    seen: set[str] = set()
    for raw in web_targets:
        target = raw if isinstance(raw, dict) else _target_to_dict(raw)
        url = _target_url(target)
        if url in seen:
            continue
        seen.add(url)
        path, note = capture_screenshot(target, out_dir, config, capturer=capturer)
        notes.append(note)
        if not path:
            continue

        host = str(target.get("host", ""))
        port = int(target.get("port", 0) or 0)
        data = {"engine": "playwright", "screenshot": path, "url": url}
        for finding in by_endpoint.get((host, port), []):
            finding.evidence.append(Evidence(
                source="engine:playwright",
                description=f"Screenshot of {url}.",
                strength=3,
                data=dict(data),
            ))
        findings.append(Finding(
            title="Web Service Screenshot Captured",
            severity=Severity.INFO,
            asset=host,
            port=port or None,
            protocol="tcp",
            service="http",
            description=f"Captured a screenshot of {url} for visual evidence.",
            recommendation="Review the screenshot to confirm the exposed interface and its sensitivity.",
            confidence=Confidence.CONFIRMED,
            evidence_strength=3,
            type="screenshot",
            module="playwright",
            false_positive_risk="low",
            manual_validation=False,
            evidence=[Evidence(
                source="engine:playwright",
                description=f"Playwright screenshot of {url}.",
                strength=3,
                data=dict(data),
            )],
            tags=["screenshot", "playwright", "optional-extra"],
            category=FindingCategory.INFORMATION,
        ))
    return findings, notes
