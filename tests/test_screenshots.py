from __future__ import annotations

import os
from pathlib import Path

from portwise.core.external_tool import ExternalTool, ExternalToolResult
from portwise.core.models import Confidence, Evidence, Finding, Severity
from portwise.intelligence.poc import build_poc_items, write_poc_artifacts
from portwise.intelligence.screenshots import capture_screenshot, run_screenshots

TARGET = {"host": "10.0.0.9", "port": 8443, "protocol": "tcp", "service": "https"}


class _FakeGowitness:
    """Simulates gowitness: on run, drops a PNG into the --screenshot-path dir."""

    def __init__(self, *, available=True, produce=True):
        self.available = available
        self._produce = produce
        self.calls: list[list[str]] = []

    def run(self, args, *, timeout=None, handoff_command=None, input_text=None):
        self.calls.append(list(args))
        result = ExternalToolResult(tool="gowitness", available=self.available, handoff_command=handoff_command)
        if not self.available:
            result.skipped_reason = "gowitness not found on PATH"
            return result
        result.ran = True
        result.returncode = 0
        if self._produce:
            # find the screenshot-path arg
            if "--screenshot-path" in args:
                d = args[args.index("--screenshot-path") + 1]
                Path(d).mkdir(parents=True, exist_ok=True)
                (Path(d) / "shot.png").write_bytes(b"\x89PNG\r\n\x1a\n")
        return result


def test_capture_screenshot_with_fake_tool(tmp_path):
    out = tmp_path / "shots"
    path, note = capture_screenshot(TARGET, str(out), {"screenshots": {"gowitness": {"enabled": True}}}, tool=_FakeGowitness())
    assert path is not None
    assert os.path.isfile(path)
    assert path.endswith(".png")
    assert "captured" in note


def test_capture_screenshot_missing_binary(tmp_path):
    path, note = capture_screenshot(
        TARGET, str(tmp_path / "shots"),
        {"screenshots": {"gowitness": {"enabled": True}}},
        tool=ExternalTool("gowitness", binary="gowitness-not-real-xyz"),
    )
    assert path is None
    assert "not installed" in note and "handoff" in note


def test_capture_disabled(tmp_path):
    path, note = capture_screenshot(TARGET, str(tmp_path), {"screenshots": {"gowitness": {"enabled": False}}}, tool=_FakeGowitness())
    assert path is None
    assert "disabled" in note


def test_capture_ran_but_no_png(tmp_path):
    path, note = capture_screenshot(TARGET, str(tmp_path / "s"), {}, tool=_FakeGowitness(produce=False))
    assert path is None
    assert "no screenshot" in note


def test_run_screenshots_attaches_to_existing_and_emits_finding(tmp_path):
    existing = Finding(title="HTTPS Service Metadata", severity=Severity.INFO, asset="10.0.0.9", port=8443)
    findings, notes = run_screenshots(
        [TARGET, TARGET],  # duplicate URL collapses
        {"screenshots": {"enabled": True, "gowitness": {"enabled": True}}},
        out_dir=str(tmp_path / "shots"),
        existing_findings=[existing],
        tool=_FakeGowitness(),
    )
    # one screenshot finding for the unique URL
    assert len(findings) == 1
    assert findings[0].title == "Web Service Screenshot Captured"
    assert findings[0].evidence[0].data["screenshot"].endswith(".png")
    # existing finding got the screenshot attached
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
