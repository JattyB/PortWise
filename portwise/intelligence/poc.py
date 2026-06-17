"""POC / evidence capture.

Turns findings into per-finding proof-of-concept artifacts the operator can
attach to a report:

* a reproduction command (nmap/openssl/curl/ssh-audit/redis-cli ...),
* an evidence text file with a slot to paste output / reference a screenshot,
* optionally, the *captured output* of safe read-only commands (``--capture``),
  which is itself attachable evidence.

Only read-only, non-exploit commands are ever executed when capturing.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Commands that are safe to actually execute during --capture (read-only).
_CAPTURE_ALLOWED = ("nmap", "curl", "openssl", "dig", "ssh-audit", "whatweb")


@dataclass(slots=True)
class PocItem:
    title: str
    severity: str
    asset: str
    port: int
    command: str
    note: str = ""
    captured_output: str = ""
    artifact_path: str = ""
    screenshot: str = ""

    def slug(self) -> str:
        base = f"{self.asset}_{self.port}_{self.title}"
        return re.sub(r"[^a-zA-Z0-9_.-]+", "_", base).strip("_")[:120]


def _poc_from_evidence(finding: dict[str, Any]) -> str | None:
    for ev in finding.get("evidence", []) or []:
        data = ev.get("data", {}) if isinstance(ev, dict) else {}
        cmd = data.get("poc_command")
        if cmd:
            return str(cmd)
    return None


def _screenshot_from_evidence(finding: dict[str, Any]) -> str | None:
    for ev in finding.get("evidence", []) or []:
        data = ev.get("data", {}) if isinstance(ev, dict) else {}
        shot = data.get("screenshot")
        if shot:
            return str(shot)
    return None


def _derive_poc(finding: dict[str, Any]) -> str | None:
    title = str(finding.get("title", "")).lower()
    host = finding.get("asset", "")
    port = finding.get("port") or 0
    if "weak ssh" in title or "deprecated ssh host key" in title:
        return f"ssh-audit {host} -p {port}"
    if "smbv1" in title:
        return f"nmap -p{port} --script smb-protocols,smb-security-mode {host}"
    if "smb signing" in title:
        return f"nmap -p{port} --script smb2-security-mode {host}"
    if "version disclosure" in title:
        return f"nmap -sV -p{port} {host}"
    if "unauthenticated redis" in title:
        return f"redis-cli -h {host} -p {port} INFO server    # or: nmap -p{port} --script redis-info {host}"
    if "memcached" in title:
        return f"nmap -p{port} --script memcached-info {host}"
    if "docker api" in title:
        return f"curl -s http://{host}:{port}/version"
    if "cleartext protocol" in title or "plaintext" in (finding.get("tags") or []):
        return f"nmap -sV -p{port} {host}"
    if "sensitive file" in title or "content discovery" in (finding.get("tags") or []):
        url = ""
        for ev in finding.get("evidence", []) or []:
            url = (ev.get("data", {}) or {}).get("url", "")
            if url:
                break
        return f"curl -sik '{url}'" if url else None
    return None


def build_poc_items(run: dict[str, Any], min_severity: str = "low") -> list[PocItem]:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4, "info": 4}
    threshold = order.get(min_severity.lower(), 3)
    items: list[PocItem] = []
    for f in run.get("findings", []) or []:
        sev = str(f.get("severity", "")).lower()
        if order.get(sev, 5) > threshold:
            continue
        cmd = _poc_from_evidence(f) or _derive_poc(f)
        screenshot = _screenshot_from_evidence(f)
        if not cmd and not screenshot:
            continue
        # Strip inline "# comment" tails for the executable form, keep full for display.
        items.append(PocItem(
            title=str(f.get("title", "")),
            severity=sev,
            asset=str(f.get("asset", "")),
            port=int(f.get("port") or 0),
            command=cmd or "",
            note=str(f.get("description", ""))[:300],
            screenshot=screenshot or "",
        ))
    return items


def _executable(command: str) -> list[str] | None:
    cmd = command.split("#", 1)[0].strip()
    if not cmd:
        return None
    parts = cmd.split()
    if parts[0] not in _CAPTURE_ALLOWED:
        return None
    if shutil.which(parts[0]) is None:
        return None
    return parts


def capture_output(command: str, timeout: int = 60) -> str:
    parts = _executable(command)
    if parts is None:
        return ""
    try:
        proc = subprocess.run(parts, capture_output=True, text=True, timeout=timeout)
        return (proc.stdout or "") + (proc.stderr or "")
    except (subprocess.TimeoutExpired, OSError) as exc:
        return f"[capture failed: {exc}]"


def write_poc_artifacts(items: list[PocItem], out_dir: Path, capture: bool = False) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    index_lines = ["# PortWise POC / Evidence Index", ""]
    for item in items:
        if capture:
            item.captured_output = capture_output(item.command)
        path = out_dir / f"{item.slug()}.txt"
        body = [
            f"Finding : {item.title}",
            f"Severity: {item.severity}",
            f"Target  : {item.asset}:{item.port}",
            "",
        ]
        if item.screenshot:
            body += [f"Screenshot evidence: {item.screenshot}", ""]
        if item.command:
            body += [
                "Reproduction command (run this and screenshot the output):",
                f"  {item.command}",
                "",
            ]
        if item.captured_output:
            body += ["----- CAPTURED OUTPUT (evidence) -----", item.captured_output.strip(), "----- END -----", ""]
        else:
            body += ["----- PASTE OUTPUT / SCREENSHOT REFERENCE BELOW -----", "", ""]
        path.write_text("\n".join(body), encoding="utf-8")
        item.artifact_path = str(path)
        index_lines.append(f"[{item.severity:>8}] {item.asset}:{item.port}  {item.title}")
        if item.command:
            index_lines.append(f"           cmd: {item.command}")
        if item.screenshot:
            index_lines.append(f"           screenshot: {item.screenshot}")
        index_lines.append(f"           file: {path.name}")
        index_lines.append("")
    index = out_dir / "INDEX.txt"
    index.write_text("\n".join(index_lines), encoding="utf-8")
    return index
