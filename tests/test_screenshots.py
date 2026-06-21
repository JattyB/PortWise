from __future__ import annotations

import os
from pathlib import Path

from portwise.core.models import Finding, Severity
from portwise.intelligence.poc import build_poc_items, write_poc_artifacts
from portwise.intelligence.screenshots import capture_screenshot, run_screenshots

TARGET = {"host": "10.0.0.9", "port": 8443, "protocol": "tcp", "service": "https"}


async def _fake_playwright_capture(url: str, dest: str, cfg: dict) -> None:
    del url, cfg
    Path(dest).parent.mkdir(parents=True, exist_ok=True)
    Path(dest).write_bytes(b"\x89PNG\r\n\x1a\n")


async def _fake_no_file_capture(url: str, dest: str, cfg: dict) -> None:
    del url, dest, cfg


async def _fake_browser_missing(url: str, dest: str, cfg: dict) -> None:
    del url, dest, cfg
    raise RuntimeError("Executable doesn't exist at chromium; run playwright install chromium")


def test_capture_screenshot_with_fake_playwright(tmp_path):
    out = tmp_path / "shots"
    path, note = capture_screenshot(
        TARGET,
        str(out),
        {"screenshots": {"playwright": {"enabled": True}}},
        capturer=_fake_playwright_capture,
    )
    assert path is not None
    assert os.path.isfile(path)
    assert path.endswith(".png")
    assert "captured" in note


def test_capture_screenshot_missing_extra(monkeypatch, tmp_path):
    monkeypatch.setattr("portwise.intelligence.screenshots._playwright_available", lambda: False)
    path, note = capture_screenshot(
        TARGET,
        str(tmp_path / "shots"),
        {"screenshots": {"playwright": {"enabled": True}}},
    )
    assert path is None
    assert "not installed" in note
    assert "portwise[screenshots]" in note


def test_capture_screenshot_missing_chromium(tmp_path):
    path, note = capture_screenshot(
        TARGET,
        str(tmp_path / "shots"),
        {"screenshots": {"playwright": {"enabled": True}}},
        capturer=_fake_browser_missing,
    )
    assert path is None
    assert "Chromium browser is not installed" in note


def test_capture_disabled(tmp_path):
    path, note = capture_screenshot(
        TARGET,
        str(tmp_path),
        {"screenshots": {"enabled": False}},
        capturer=_fake_playwright_capture,
    )
    assert path is None
    assert "disabled" in note


def test_capture_ran_but_no_png(tmp_path):
    path, note = capture_screenshot(TARGET, str(tmp_path / "s"), {}, capturer=_fake_no_file_capture)
    assert path is None
    assert "no screenshot" in note


def test_run_screenshots_attaches_to_existing_and_emits_finding(tmp_path):
    existing = Finding(title="HTTPS Service Metadata", severity=Severity.INFO, asset="10.0.0.9", port=8443)
    findings, notes = run_screenshots(
        [TARGET, TARGET],
        {"screenshots": {"enabled": True, "playwright": {"enabled": True}}},
        out_dir=str(tmp_path / "shots"),
        existing_findings=[existing],
        capturer=_fake_playwright_capture,
    )
    assert len(findings) == 1
    assert findings[0].title == "Web Service Screenshot Captured"
    assert findings[0].module == "playwright"
    assert findings[0].evidence[0].data["screenshot"].endswith(".png")
    assert findings[0].evidence[0].data["engine"] == "playwright"
    assert notes == ["playwright: captured https://10.0.0.9:8443"]
    assert any(ev.data.get("screenshot") for ev in existing.evidence)


def test_run_screenshots_disabled():
    findings, notes = run_screenshots([TARGET], {"screenshots": {"enabled": False}}, out_dir="x")
    assert findings == []
    assert notes == ["screenshots: disabled by config"]


def test_poc_bundle_includes_screenshot(tmp_path):
    shot = tmp_path / "evidence" / "s.png"
    shot.parent.mkdir(parents=True, exist_ok=True)
    shot.write_bytes(b"\x89PNG")
    run = {
        "findings": [
            {
                "title": "Web Service Screenshot Captured",
                "severity": "informational",
                "asset": "10.0.0.9",
                "port": 8443,
                "evidence": [{"data": {"screenshot": str(shot), "url": "https://10.0.0.9:8443"}}],
            }
        ]
    }
    items = build_poc_items(run, min_severity="informational")
    assert len(items) == 1
    assert items[0].screenshot == str(shot)
    index = write_poc_artifacts(items, tmp_path / "poc")
    body = (tmp_path / "poc" / f"{items[0].slug()}.txt").read_text(encoding="utf-8")
    assert "Screenshot evidence" in body
    assert "screenshot" in index.read_text(encoding="utf-8")
