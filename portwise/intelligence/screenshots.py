"""Optional screenshot evidence via gowitness.

When gowitness is on PATH, PortWise screenshots each discovered web service and
attaches the image path to the relevant findings (and a dedicated screenshot
finding) so the report and POC bundle can show visual proof. Absent the binary,
it skips cleanly and records the equivalent handoff command.

gowitness CLI syntax has changed across major versions, so we try a few argument
forms and accept whichever one actually produces a PNG in the output directory.
"""
from __future__ import annotations

import glob
import os
import re
import tempfile
from typing import Any

from portwise.core.external_tool import ExternalTool
from portwise.core.models import Confidence, Evidence, Finding, FindingCategory, Severity
from portwise.intelligence.web_engines import _target_to_dict, _target_url

# gowitness argument forms, newest syntax first. The first form that drops a PNG
# into the output directory wins.
_ARG_FORMS = (
    lambda url, d: ["scan", "single", "--url", url, "--screenshot-path", d, "--write-db=false"],
    lambda url, d: ["single", "--url", url, "--screenshot-path", d],
    lambda url, d: ["single", url, "--screenshot-path", d],
)


def _gowitness_cfg(config: dict[str, Any]) -> dict[str, Any]:
    shots = config.get("screenshots", {}) if isinstance(config.get("screenshots"), dict) else {}
    section = shots.get("gowitness", {})
    return section if isinstance(section, dict) else {}


def _slug(url: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]+", "_", url).strip("_")[:120] or "screenshot"


def _newest_png(directory: str) -> str | None:
    pngs = glob.glob(os.path.join(directory, "**", "*.png"), recursive=True)
    if not pngs:
        return None
    return max(pngs, key=lambda p: os.path.getmtime(p))


def capture_screenshot(
    target: dict[str, Any],
    out_dir: str,
    config: dict[str, Any],
    *,
    tool: ExternalTool | None = None,
) -> tuple[str | None, str]:
    """Screenshot one web target. Returns (image_path_or_None, status_note)."""
    cfg = _gowitness_cfg(config)
    if not bool(cfg.get("enabled", True)):
        return None, "gowitness: disabled by config"
    url = _target_url(target)
    handoff = f"gowitness scan single --url {url} --screenshot-path screenshots/"
    tool = tool or ExternalTool("gowitness", timeout=float(cfg.get("timeout", 60)))
    if not tool.available:
        return None, f"gowitness: not installed; skipped — handoff: {handoff}"

    os.makedirs(out_dir, exist_ok=True)
    shot_dir = tempfile.mkdtemp(prefix="pw-shot-", dir=out_dir)
    for build in _ARG_FORMS:
        args = build(url, shot_dir)
        extra = cfg.get("extra_args")
        if isinstance(extra, list):
            args = args + [str(a) for a in extra]
        result = tool.run(args, handoff_command=handoff)
        if not result.available:
            return None, result.note()
        png = _newest_png(shot_dir)
        if png:
            dest = os.path.join(out_dir, f"{_slug(url)}.png")
            try:
                os.replace(png, dest)
            except OSError:
                dest = png
            return dest, f"gowitness: captured {url}"
    return None, f"gowitness: ran but produced no screenshot for {url} — handoff: {handoff}"


def run_screenshots(
    web_targets: list[Any],
    config: dict[str, Any],
    *,
    out_dir: str,
    existing_findings: list[Finding] | None = None,
    tool: ExternalTool | None = None,
) -> tuple[list[Finding], list[str]]:
    """Screenshot each unique web target; attach paths to matching findings and
    emit a dedicated screenshot finding per capture. Returns (findings, notes)."""
    shots_cfg = config.get("screenshots", {}) if isinstance(config.get("screenshots"), dict) else {}
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
        path, note = capture_screenshot(target, out_dir, config, tool=tool)
        notes.append(note)
        if not path:
            continue
        host = str(target.get("host", ""))
        port = int(target.get("port", 0) or 0)
        data = {"engine": "gowitness", "screenshot": path, "url": url}
        # Attach to existing findings on this endpoint so the report shows the image inline.
        for finding in by_endpoint.get((host, port), []):
            finding.evidence.append(Evidence(
                source="engine:gowitness",
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
            module="gowitness",
            false_positive_risk="low",
            manual_validation=False,
            evidence=[Evidence(
                source="engine:gowitness",
                description=f"gowitness screenshot of {url}.",
                strength=3,
                data=dict(data),
            )],
            tags=["screenshot", "external-engine"],
            category=FindingCategory.INFORMATION,
        ))
    return findings, notes
